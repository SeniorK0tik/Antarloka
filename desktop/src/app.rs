//! egui front-end.
//!
//! The UI owns no networking state: it drains [`EngineEvent`]s into local
//! display structures and calls engine methods. Every security decision
//! (pairing, accepting a file) is an explicit click here and is enforced in the
//! engine, never in this file.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use egui::{Color32, RichText};

use syncmob::config::{Config, Paths};
use syncmob::engine::{Engine, EngineEvent};
use syncmob::proto::TransferId;
use syncmob::security::keystore::KeystoreState;
use syncmob::security::{DeviceId, Identity, TrustStore};
use syncmob::util::human_bytes;

const GREEN: Color32 = Color32::from_rgb(90, 200, 120);
const AMBER: Color32 = Color32::from_rgb(230, 170, 60);
const RED: Color32 = Color32::from_rgb(225, 95, 95);
const DIM: Color32 = Color32::from_rgb(150, 150, 160);

pub struct App {
    phase: Phase,
}

enum Phase {
    Unlock(Unlock),
    Running(Box<Running>),
}

// ---------------------------------------------------------------- unlock

struct Unlock {
    paths: Paths,
    state: KeystoreState,
    device_name: String,
    pass: String,
    pass_confirm: String,
    no_passphrase: bool,
    error: String,
    busy: bool,
}

impl Unlock {
    fn new() -> Self {
        let paths = Paths::discover();
        let state = Identity::state(&paths.identity());
        let cfg = Config::load(&paths.config());
        Self {
            paths,
            state,
            device_name: cfg.device_name,
            pass: String::new(),
            pass_confirm: String::new(),
            no_passphrase: false,
            error: String::new(),
            busy: false,
        }
    }
}

// --------------------------------------------------------------- running

#[derive(Clone)]
struct ChatItem {
    stamp: String,
    mine: bool,
    text: String,
    system: bool,
}

#[derive(Clone)]
struct TransferRow {
    name: String,
    size: u64,
    done: u64,
    incoming: bool,
    peer: DeviceId,
    finished: bool,
    error: Option<String>,
    path: Option<PathBuf>,
}

#[derive(Clone)]
struct PairPrompt {
    device: DeviceId,
    name: String,
    fingerprint: String,
    sas: String,
    addr: SocketAddr,
    remote_initiated: bool,
}

#[derive(Clone)]
struct OfferPrompt {
    transfer: TransferId,
    from: DeviceId,
    name: String,
    size: u64,
}

struct Running {
    engine: Engine,
    paths: Paths,
    config: Config,
    draft_config: Config,
    unprotected_key: bool,

    selected: Option<DeviceId>,
    chats: BTreeMap<DeviceId, Vec<ChatItem>>,
    names: BTreeMap<DeviceId, String>,
    connected: BTreeMap<DeviceId, bool>,
    input: String,
    manual_addr: String,
    paste_uri: String,

    pairing: Option<PairPrompt>,
    offers: VecDeque<OfferPrompt>,
    transfers: BTreeMap<TransferId, TransferRow>,
    log: VecDeque<(String, Color32)>,

    show_settings: bool,
    show_qr: bool,
    show_identity: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            phase: Phase::Unlock(Unlock::new()),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Network events arrive on other threads; repaint regularly so the UI
        // does not sit idle while a transfer is running.
        ctx.request_repaint_after(Duration::from_millis(250));

        let mut next: Option<Phase> = None;
        match &mut self.phase {
            Phase::Unlock(u) => {
                if let Some(running) = unlock_ui(ctx, u) {
                    next = Some(Phase::Running(Box::new(running)));
                }
            }
            Phase::Running(r) => {
                r.pump_events();
                r.ui(ctx);
            }
        }
        if let Some(n) = next {
            self.phase = n;
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Phase::Running(r) = &mut self.phase {
            r.engine.shutdown();
        }
    }
}

// ---------------------------------------------------------------- unlock UI

fn unlock_ui(ctx: &egui::Context, u: &mut Unlock) -> Option<Running> {
    let mut result = None;
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.add_space(60.0);
        ui.vertical_centered(|ui| {
            ui.heading("SyncMob");
            ui.label(RichText::new("Зашифрованный обмен файлами и сообщениями в локальной сети").color(DIM));
            ui.add_space(24.0);
        });

        let width = 460.0;
        ui.vertical_centered(|ui| {
            ui.allocate_ui(egui::vec2(width, 360.0), |ui| match u.state {
                KeystoreState::Missing => {
                    ui.label(RichText::new("Первый запуск").strong());
                    ui.add_space(6.0);
                    ui.label("Имя устройства (видно другим в сети):");
                    ui.add(egui::TextEdit::singleline(&mut u.device_name).desired_width(width));
                    ui.add_space(12.0);

                    ui.checkbox(
                        &mut u.no_passphrase,
                        "Не защищать ключ паролем (не рекомендуется)",
                    );
                    if u.no_passphrase {
                        ui.label(
                            RichText::new(
                                "Приватный ключ будет лежать на диске в открытом виде. \
                                 Любая программа, запущенная от вашего имени, сможет его \
                                 прочитать и выдать себя за это устройство.",
                            )
                            .color(AMBER)
                            .small(),
                        );
                    } else {
                        ui.label("Пароль для защиты приватного ключа:");
                        ui.add(
                            egui::TextEdit::singleline(&mut u.pass)
                                .password(true)
                                .desired_width(width),
                        );
                        ui.label("Повторите пароль:");
                        ui.add(
                            egui::TextEdit::singleline(&mut u.pass_confirm)
                                .password(true)
                                .desired_width(width),
                        );
                        ui.label(
                            RichText::new(
                                "Пароль нигде не хранится и не восстанавливается. \
                                 Забыли — придётся создать новое устройство и заново пройти сопряжение.",
                            )
                            .color(DIM)
                            .small(),
                        );
                    }

                    ui.add_space(14.0);
                    if ui.add(egui::Button::new("Создать устройство").min_size(egui::vec2(width, 32.0))).clicked()
                        && !u.busy
                    {
                        u.error.clear();
                        if !u.no_passphrase && u.pass.chars().count() < 8 {
                            u.error = "Пароль должен быть не короче 8 символов".into();
                        } else if !u.no_passphrase && u.pass != u.pass_confirm {
                            u.error = "Пароли не совпадают".into();
                        } else {
                            u.busy = true;
                            let pass = (!u.no_passphrase).then(|| u.pass.clone());
                            match create_identity(u, pass.as_deref()) {
                                Ok(r) => result = Some(r),
                                Err(e) => u.error = e,
                            }
                            u.busy = false;
                        }
                    }
                }
                KeystoreState::Encrypted => {
                    ui.label(RichText::new("Разблокировка").strong());
                    ui.add_space(6.0);
                    ui.label("Пароль от приватного ключа:");
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut u.pass)
                            .password(true)
                            .desired_width(width),
                    );
                    let submit = ui
                        .add(egui::Button::new("Войти").min_size(egui::vec2(width, 32.0)))
                        .clicked()
                        || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                    if submit && !u.busy {
                        u.busy = true;
                        u.error.clear();
                        match open_identity(u, Some(u.pass.clone().as_str())) {
                            Ok(r) => result = Some(r),
                            Err(e) => u.error = e,
                        }
                        u.pass.clear();
                        u.busy = false;
                    }
                }
                KeystoreState::Plaintext => {
                    ui.label(
                        RichText::new("Ключ этого устройства не защищён паролем.")
                            .color(AMBER),
                    );
                    ui.add_space(10.0);
                    if ui.add(egui::Button::new("Продолжить").min_size(egui::vec2(width, 32.0))).clicked() {
                        match open_identity(u, None) {
                            Ok(r) => result = Some(r),
                            Err(e) => u.error = e,
                        }
                    }
                }
            });

            if !u.error.is_empty() {
                ui.add_space(10.0);
                ui.label(RichText::new(&u.error).color(RED));
            }
        });
    });
    result
}

fn create_identity(u: &Unlock, pass: Option<&str>) -> Result<Running, String> {
    let mut identity = Identity::generate().map_err(|e| e.to_string())?;
    identity
        .save(&u.paths.identity(), pass)
        .map_err(|e| format!("Не удалось сохранить ключ: {e}"))?;
    let mut cfg = Config::load(&u.paths.config());
    cfg.device_name = syncmob::util::clamp_str(u.device_name.trim(), 32);
    if cfg.device_name.is_empty() {
        cfg.device_name = "SyncMob PC".into();
    }
    let _ = cfg.save(&u.paths.config());
    let trust = TrustStore::new();
    trust
        .save(&u.paths.trust(), &identity)
        .map_err(|e| e.to_string())?;
    Running::start(identity, cfg, u.paths.clone(), trust, pass.is_none())
}

fn open_identity(u: &Unlock, pass: Option<&str>) -> Result<Running, String> {
    let identity = Identity::load(&u.paths.identity(), pass).map_err(|e| e.to_string())?;
    let trust = TrustStore::load(&u.paths.trust(), &identity).map_err(|e| {
        format!("{e}. Удалите trust.json, чтобы начать со сброшенным списком доверия.")
    })?;
    let cfg = Config::load(&u.paths.config());
    Running::start(identity, cfg, u.paths.clone(), trust, pass.is_none())
}

// --------------------------------------------------------------- running UI

impl Running {
    fn start(
        identity: Identity,
        config: Config,
        paths: Paths,
        trust: TrustStore,
        unprotected_key: bool,
    ) -> Result<Self, String> {
        let engine = Engine::start(identity, config.clone(), paths.clone(), trust)
            .map_err(|e| format!("Не удалось запустить сеть: {e}"))?;
        Ok(Self {
            engine,
            paths,
            draft_config: config.clone(),
            config,
            unprotected_key,
            selected: None,
            chats: BTreeMap::new(),
            names: BTreeMap::new(),
            connected: BTreeMap::new(),
            input: String::new(),
            manual_addr: String::new(),
            paste_uri: String::new(),
            pairing: None,
            offers: VecDeque::new(),
            transfers: BTreeMap::new(),
            log: VecDeque::new(),
            show_settings: false,
            show_qr: false,
            show_identity: false,
        })
    }

    fn note(&mut self, text: impl Into<String>, color: Color32) {
        let line = format!("{}  {}", stamp_now(), text.into());
        self.log.push_back((line, color));
        while self.log.len() > 300 {
            self.log.pop_front();
        }
    }

    fn push_chat(&mut self, device: DeviceId, item: ChatItem) {
        let v = self.chats.entry(device).or_default();
        v.push(item);
        if v.len() > 1000 {
            v.drain(..v.len() - 1000);
        }
    }

    fn name_of(&self, id: DeviceId) -> String {
        self.names
            .get(&id)
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| id.to_string())
    }

    fn pump_events(&mut self) {
        let events: Vec<EngineEvent> = self.engine.events.try_iter().collect();
        for ev in events {
            match ev {
                EngineEvent::PeerDiscovered(p) => {
                    self.names.insert(p.device, p.name.clone());
                    self.note(format!("Найдено устройство: {} ({})", p.name, p.addr), DIM);
                }
                EngineEvent::PeerLost(id) => {
                    self.note(
                        format!("Устройство {} пропало из сети", self.name_of(id)),
                        DIM,
                    );
                }
                EngineEvent::Connected(c) => {
                    if !c.name.is_empty() {
                        self.names.insert(c.device, c.name.clone());
                    }
                    self.connected.insert(c.device, c.paired);
                    if c.paired {
                        let n = self.name_of(c.device);
                        self.note(format!("Установлено защищённое соединение с {n}"), GREEN);
                        if self.selected.is_none() {
                            self.selected = Some(c.device);
                        }
                    }
                }
                EngineEvent::Disconnected { device, reason } => {
                    self.connected.remove(&device);
                    let n = self.name_of(device);
                    self.note(format!("Соединение с {n} закрыто: {reason}"), DIM);
                }
                EngineEvent::PairingRequired {
                    device,
                    name,
                    fingerprint,
                    sas,
                    addr,
                    remote_initiated,
                } => {
                    if !name.is_empty() {
                        self.names.insert(device, name.clone());
                    }
                    self.pairing = Some(PairPrompt {
                        device,
                        name: self.name_of(device),
                        fingerprint,
                        sas,
                        addr,
                        remote_initiated,
                    });
                }
                EngineEvent::PairingFinished { device, accepted } => {
                    if self.pairing.as_ref().map(|p| p.device) == Some(device) {
                        self.pairing = None;
                    }
                    let n = self.name_of(device);
                    if accepted {
                        self.note(format!("Устройство {n} сопряжено"), GREEN);
                        self.selected = Some(device);
                    } else {
                        self.note(format!("Сопряжение с {n} отклонено"), AMBER);
                    }
                }
                EngineEvent::TextReceived { from, text, ts } => {
                    self.push_chat(
                        from,
                        ChatItem {
                            stamp: stamp(ts),
                            mine: false,
                            text,
                            system: false,
                        },
                    );
                }
                EngineEvent::TextSent { to, text, ts } => {
                    self.push_chat(
                        to,
                        ChatItem {
                            stamp: stamp(ts),
                            mine: true,
                            text,
                            system: false,
                        },
                    );
                }
                EngineEvent::OfferReceived {
                    from,
                    transfer,
                    name,
                    size,
                } => {
                    self.offers.push_back(OfferPrompt {
                        transfer,
                        from,
                        name,
                        size,
                    });
                }
                EngineEvent::TransferProgress {
                    transfer,
                    done,
                    total,
                    incoming,
                } => {
                    let e = self.transfers.entry(transfer).or_insert(TransferRow {
                        name: String::new(),
                        size: total,
                        done: 0,
                        incoming,
                        peer: self
                            .selected
                            .unwrap_or(DeviceId::parse("0000000000000000").unwrap()),
                        finished: false,
                        error: None,
                        path: None,
                    });
                    e.done = done;
                    e.size = total;
                }
                EngineEvent::TransferFinished {
                    transfer,
                    incoming,
                    name,
                    path,
                    error,
                } => {
                    let peer = self
                        .transfers
                        .get(&transfer)
                        .map(|t| t.peer)
                        .or(self.selected)
                        .unwrap_or(DeviceId::parse("0000000000000000").unwrap());
                    self.transfers.insert(
                        transfer,
                        TransferRow {
                            name: name.clone(),
                            size: 0,
                            done: 0,
                            incoming,
                            peer,
                            finished: true,
                            error: error.clone(),
                            path: path.clone(),
                        },
                    );
                    let text = match (&error, &path) {
                        (Some(e), _) => format!("✖ Файл «{name}» не передан: {e}"),
                        (None, Some(p)) => format!("✔ Файл «{name}» сохранён: {}", p.display()),
                        (None, None) => format!("✔ Файл «{name}» отправлен"),
                    };
                    let color = if error.is_some() { RED } else { GREEN };
                    self.note(text.clone(), color);
                    self.push_chat(
                        peer,
                        ChatItem {
                            stamp: stamp_now(),
                            mine: !incoming,
                            text,
                            system: true,
                        },
                    );
                }
                EngineEvent::TrustChanged => {}
                EngineEvent::Notice(m) => self.note(m, DIM),
                EngineEvent::Error(m) => self.note(m, RED),
            }
        }
    }

    fn ui(&mut self, ctx: &egui::Context) {
        self.top_bar(ctx);
        self.left_panel(ctx);
        self.bottom_panel(ctx);
        self.central(ctx);
        self.modals(ctx);
    }

    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("SyncMob");
                ui.separator();
                ui.label(RichText::new(&self.config.device_name).strong());
                ui.label(
                    RichText::new(format!(
                        "ID {}  •  порт {}",
                        self.engine.device_id(),
                        self.engine.port()
                    ))
                    .color(DIM),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Настройки").clicked() {
                        self.draft_config = self.config.clone();
                        self.show_settings = true;
                    }
                    if ui.button("Мой отпечаток").clicked() {
                        self.show_identity = true;
                    }
                    if ui.button("QR для сопряжения").clicked() {
                        self.show_qr = true;
                    }
                });
            });
            if self.unprotected_key {
                ui.label(
                    RichText::new(
                        "⚠ Приватный ключ хранится без пароля — задайте пароль в настройках безопасности.",
                    )
                    .color(AMBER)
                    .small(),
                );
            }
            ui.add_space(4.0);
        });
    }

    fn left_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("devices")
            .resizable(true)
            .default_width(330.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.label(RichText::new("Подключиться по адресу").strong());
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.manual_addr)
                            .hint_text("192.168.1.42:45821")
                            .desired_width(200.0),
                    );
                    if ui.button("Связаться").clicked() {
                        match self.manual_addr.trim().parse::<SocketAddr>() {
                            Ok(a) => self.engine.dial(a, None),
                            Err(_) => self.note("Неверный адрес. Формат: IP:порт", RED),
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.paste_uri)
                            .hint_text("syncmob://pair?…")
                            .desired_width(200.0),
                    );
                    if ui.button("По ссылке").clicked() {
                        let uri = self.paste_uri.trim().to_string();
                        match self.engine.dial_pairing_uri(&uri) {
                            Ok(()) => self.paste_uri.clear(),
                            Err(e) => self.note(format!("Ссылка сопряжения: {e}"), RED),
                        }
                    }
                });

                ui.add_space(10.0);
                ui.separator();

                let trusted = self.engine.trusted();
                let peers = self.engine.peers();
                let conns = self.engine.connections();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.label(RichText::new("Доверенные устройства").strong());
                    if trusted.is_empty() {
                        ui.label(RichText::new("пока нет").color(DIM).small());
                    }
                    for d in &trusted {
                        let Some(id) = d.device_id() else { continue };
                        if !d.name.is_empty() {
                            self.names.insert(id, d.name.clone());
                        }
                        let online = peers.iter().any(|p| p.device == id);
                        let connected = conns.iter().any(|c| c.device == id && c.paired);
                        self.device_row(ui, id, &d.name, online, connected, d.blocked, true);
                    }

                    ui.add_space(12.0);
                    ui.label(RichText::new("Найдены в сети").strong());
                    let unknown: Vec<_> = peers.iter().filter(|p| !p.paired).collect();
                    if unknown.is_empty() {
                        ui.label(RichText::new("новых устройств нет").color(DIM).small());
                    }
                    for p in unknown {
                        self.names.insert(p.device, p.name.clone());
                        let connected = conns.iter().any(|c| c.device == p.device);
                        self.device_row(ui, p.device, &p.name, true, connected, false, false);
                    }
                });
            });
    }

    #[allow(clippy::too_many_arguments)]
    fn device_row(
        &mut self,
        ui: &mut egui::Ui,
        id: DeviceId,
        name: &str,
        online: bool,
        connected: bool,
        blocked: bool,
        paired: bool,
    ) {
        let selected = self.selected == Some(id);
        let dot = if blocked {
            RichText::new("■").color(RED)
        } else if connected {
            RichText::new("●").color(GREEN)
        } else if online {
            RichText::new("●").color(AMBER)
        } else {
            RichText::new("●").color(DIM)
        };
        let label = if name.is_empty() {
            id.to_string()
        } else {
            name.to_string()
        };

        ui.horizontal(|ui| {
            ui.label(dot);
            if ui
                .selectable_label(selected, RichText::new(label).strong())
                .clicked()
            {
                self.selected = Some(id);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if connected {
                    if ui.small_button("Отключить").clicked() {
                        self.engine.disconnect(id);
                    }
                } else if online
                    && !blocked
                    && ui
                        .small_button(if paired {
                            "Подключить"
                        } else {
                            "Сопрячь"
                        })
                        .clicked()
                {
                    self.engine.connect(id);
                }
            });
        });
        ui.label(RichText::new(format!("   {id}")).color(DIM).small());
    }

    fn central(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(device) = self.selected else {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("Выберите устройство слева").color(DIM));
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(
                            "Новые устройства нужно один раз сопрячь: обе стороны сверяют \
                             восьмизначный код и подтверждают его.",
                        )
                        .color(DIM)
                        .small(),
                    );
                });
                return;
            };

            let trusted = self
                .engine
                .trusted()
                .into_iter()
                .find(|d| d.device_id() == Some(device));
            let conn = self
                .engine
                .connections()
                .into_iter()
                .find(|c| c.device == device);
            let name = self.name_of(device);

            ui.horizontal(|ui| {
                ui.heading(&name);
                match &conn {
                    Some(c) if c.paired => ui.label(RichText::new("• на связи").color(GREEN)),
                    Some(_) => ui.label(RichText::new("• ожидает сопряжения").color(AMBER)),
                    None => ui.label(RichText::new("• не подключено").color(DIM)),
                };
            });
            if let Some(d) = &trusted {
                ui.label(
                    RichText::new(format!("Отпечаток ключа: {}", d.fingerprint()))
                        .color(DIM)
                        .small(),
                );
                ui.horizontal(|ui| {
                    let mut auto = d.auto_accept_files;
                    if ui
                        .checkbox(&mut auto, "Принимать файлы без подтверждения")
                        .on_hover_text(
                            "Файлы от этого устройства будут сохраняться сразу. \
                             Включайте только для устройств, которыми управляете вы сами.",
                        )
                        .changed()
                    {
                        self.engine.set_auto_accept(device, auto);
                    }
                    let mut blocked = d.blocked;
                    if ui.checkbox(&mut blocked, "Заблокировать").changed() {
                        self.engine.set_blocked(device, blocked);
                    }
                    if ui.button("Забыть устройство").clicked() {
                        self.engine.forget(device);
                        self.selected = None;
                    }
                });
            }
            ui.separator();

            let can_send = conn.as_ref().map(|c| c.paired).unwrap_or(false);
            let items = self.chats.get(&device).cloned().unwrap_or_default();

            let bottom = 92.0;
            let height = (ui.available_height() - bottom).max(80.0);
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .max_height(height)
                .show(ui, |ui| {
                    if items.is_empty() {
                        ui.label(RichText::new("Сообщений пока нет").color(DIM).small());
                    }
                    for it in &items {
                        let who = if it.system {
                            RichText::new(format!("{}  •", it.stamp)).color(DIM).small()
                        } else if it.mine {
                            RichText::new(format!("{}  Вы", it.stamp))
                                .color(DIM)
                                .small()
                        } else {
                            RichText::new(format!("{}  {}", it.stamp, name))
                                .color(DIM)
                                .small()
                        };
                        ui.label(who);
                        let body = if it.system {
                            RichText::new(&it.text).italics().color(DIM)
                        } else {
                            RichText::new(&it.text)
                        };
                        ui.label(body);
                        ui.add_space(4.0);
                    }
                });

            ui.separator();
            ui.horizontal(|ui| {
                let resp = ui.add_enabled(
                    can_send,
                    egui::TextEdit::singleline(&mut self.input)
                        .hint_text("Сообщение…")
                        .desired_width(ui.available_width() - 200.0),
                );
                let send = ui
                    .add_enabled(can_send, egui::Button::new("Отправить"))
                    .clicked()
                    || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                if send && can_send && !self.input.trim().is_empty() {
                    let text = std::mem::take(&mut self.input);
                    self.engine.send_text(device, &text);
                    resp.request_focus();
                }
                if ui
                    .add_enabled(can_send, egui::Button::new("Файл…"))
                    .clicked()
                {
                    if let Some(files) = rfd::FileDialog::new().pick_files() {
                        for f in files {
                            self.engine.send_file(device, f);
                        }
                    }
                }
            });
            if !can_send {
                ui.label(
                    RichText::new("Подключитесь к устройству, чтобы отправлять сообщения и файлы.")
                        .color(DIM)
                        .small(),
                );
            }
        });
    }

    fn bottom_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status")
            .resizable(true)
            .default_height(170.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Передачи").strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Очистить журнал").clicked() {
                            self.log.clear();
                            self.transfers.retain(|_, t| !t.finished);
                        }
                    });
                });

                let active: Vec<(TransferId, TransferRow)> = self
                    .transfers
                    .iter()
                    .filter(|(_, t)| !t.finished)
                    .map(|(id, t)| (*id, t.clone()))
                    .collect();
                if active.is_empty() {
                    ui.label(RichText::new("активных передач нет").color(DIM).small());
                }
                for (id, t) in active {
                    ui.horizontal(|ui| {
                        let arrow = if t.incoming { "↓" } else { "↑" };
                        let label = if t.name.is_empty() {
                            id.short()
                        } else {
                            t.name.clone()
                        };
                        ui.label(format!("{arrow} {label}"));
                        let frac = if t.size == 0 {
                            0.0
                        } else {
                            t.done as f32 / t.size as f32
                        };
                        ui.add(
                            egui::ProgressBar::new(frac)
                                .desired_width(260.0)
                                .text(format!("{} / {}", human_bytes(t.done), human_bytes(t.size))),
                        );
                        if ui.small_button("Отменить").clicked() {
                            self.engine.cancel_transfer(id);
                        }
                    });
                }

                let finished: Vec<TransferRow> = self
                    .transfers
                    .values()
                    .filter(|t| t.finished)
                    .rev()
                    .take(5)
                    .cloned()
                    .collect();
                for t in finished {
                    ui.horizontal(|ui| match (&t.error, &t.path) {
                        (Some(e), _) => {
                            ui.label(RichText::new(format!("✖ {}", t.name)).color(RED));
                            ui.label(RichText::new(e).color(RED).small());
                        }
                        (None, Some(path)) => {
                            ui.label(RichText::new(format!("✔ {}", t.name)).color(GREEN));
                            if ui.small_button("Открыть папку").clicked() {
                                if let Some(dir) = path.parent() {
                                    open_in_file_manager(dir);
                                }
                            }
                        }
                        (None, None) => {
                            ui.label(RichText::new(format!("✔ {} отправлен", t.name)).color(GREEN));
                        }
                    });
                }

                ui.separator();
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for (line, color) in &self.log {
                            ui.label(RichText::new(line).color(*color).small());
                        }
                    });
            });
    }

    fn modals(&mut self, ctx: &egui::Context) {
        self.pairing_modal(ctx);
        self.offer_modal(ctx);
        self.qr_window(ctx);
        self.identity_window(ctx);
        self.settings_window(ctx);
    }

    fn pairing_modal(&mut self, ctx: &egui::Context) {
        let Some(p) = self.pairing.clone() else {
            return;
        };
        let mut decision: Option<bool> = None;
        egui::Window::new("Подтверждение сопряжения")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(460.0);
                let who = if p.name.is_empty() {
                    p.device.to_string()
                } else {
                    p.name.clone()
                };
                if p.remote_initiated {
                    ui.label(format!(
                        "Устройство «{who}» ({}) хочет установить связь.",
                        p.addr
                    ));
                } else {
                    ui.label(format!("Вы подключаетесь к «{who}» ({}).", p.addr));
                }
                ui.add_space(10.0);
                ui.label(RichText::new("Код сверки").strong());
                ui.label(RichText::new(&p.sas).monospace().size(34.0).color(GREEN));
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "Убедитесь, что на втором устройстве показан ровно такой же код. \
                         Если коды различаются — соединение перехвачено, нажмите «Отклонить».",
                    )
                    .color(AMBER),
                );
                ui.add_space(10.0);
                ui.label(
                    RichText::new("Отпечаток ключа собеседника")
                        .strong()
                        .small(),
                );
                ui.label(RichText::new(&p.fingerprint).monospace().small());
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(
                            RichText::new("Подтвердить и сопрячь").strong(),
                        ))
                        .clicked()
                    {
                        decision = Some(true);
                    }
                    if ui.button("Отклонить").clicked() {
                        decision = Some(false);
                    }
                });
            });
        if let Some(accept) = decision {
            self.engine.respond_pairing(p.device, accept);
            self.pairing = None;
        }
    }

    fn offer_modal(&mut self, ctx: &egui::Context) {
        let Some(o) = self.offers.front().cloned() else {
            return;
        };
        let mut decision: Option<bool> = None;
        egui::Window::new("Входящий файл")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 40.0])
            .show(ctx, |ui| {
                ui.set_min_width(420.0);
                ui.label(format!(
                    "Устройство «{}» предлагает файл:",
                    self.name_of(o.from)
                ));
                ui.add_space(6.0);
                ui.label(RichText::new(&o.name).strong());
                ui.label(RichText::new(human_bytes(o.size)).color(DIM));
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!(
                        "Будет сохранён в {}",
                        self.config.download_dir.display()
                    ))
                    .color(DIM)
                    .small(),
                );
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(RichText::new("Принять").strong()))
                        .clicked()
                    {
                        decision = Some(true);
                    }
                    if ui.button("Отклонить").clicked() {
                        decision = Some(false);
                    }
                });
            });
        if let Some(accept) = decision {
            self.offers.pop_front();
            self.engine.respond_offer(o.transfer, accept);
            if accept {
                self.transfers.insert(
                    o.transfer,
                    TransferRow {
                        name: o.name,
                        size: o.size,
                        done: 0,
                        incoming: true,
                        peer: o.from,
                        finished: false,
                        error: None,
                        path: None,
                    },
                );
            }
        }
    }

    fn qr_window(&mut self, ctx: &egui::Context) {
        if !self.show_qr {
            return;
        }
        let uri = self.engine.pairing_uri();
        let mut open = true;
        egui::Window::new("QR для сопряжения")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label("Отсканируйте этот код в мобильном приложении SyncMob:");
                ui.add_space(8.0);
                ui.vertical_centered(|ui| {
                    if let Err(e) = crate::qr::draw(ui, &uri, 300.0) {
                        ui.label(RichText::new(format!("Не удалось построить QR: {e}")).color(RED));
                    }
                });
                ui.add_space(8.0);
                ui.label(RichText::new(&uri).monospace().small());
                if ui.button("Скопировать ссылку").clicked() {
                    ui.ctx().copy_text(uri.clone());
                }
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "В коде содержится публичный ключ этого ПК. Телефон сверит его \
                         при подключении — подменить соединение не получится. \
                         Подтверждение на этой стороне всё равно потребуется.",
                    )
                    .color(DIM)
                    .small(),
                );
            });
        self.show_qr = open;
    }

    fn identity_window(&mut self, ctx: &egui::Context) {
        if !self.show_identity {
            return;
        }
        let mut open = true;
        egui::Window::new("Отпечаток этого устройства")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(self.engine.fingerprint())
                        .monospace()
                        .size(18.0),
                );
                ui.add_space(6.0);
                ui.label(RichText::new(format!("ID: {}", self.engine.device_id())).color(DIM));
                if let Some(ip) = syncmob::engine::local_ipv4() {
                    ui.label(
                        RichText::new(format!("Адрес: {ip}:{}", self.engine.port())).color(DIM),
                    );
                }
                ui.add_space(8.0);
                if ui.button("Скопировать отпечаток").clicked() {
                    ui.ctx().copy_text(self.engine.fingerprint());
                }
            });
        self.show_identity = open;
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        if !self.show_settings {
            return;
        }
        let mut open = true;
        let mut apply = false;
        egui::Window::new("Настройки")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.set_min_width(520.0);
                ui.label(RichText::new("Общие").strong());
                ui.horizontal(|ui| {
                    ui.label("Имя устройства:");
                    ui.text_edit_singleline(&mut self.draft_config.device_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Папка для входящих файлов:");
                    ui.label(
                        RichText::new(self.draft_config.download_dir.display().to_string())
                            .color(DIM),
                    );
                    if ui.small_button("Выбрать…").clicked() {
                        if let Some(d) = rfd::FileDialog::new().pick_folder() {
                            self.draft_config.download_dir = d;
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("TCP-порт (применится после перезапуска):");
                    let mut port = self.draft_config.tcp_port.to_string();
                    if ui
                        .add(egui::TextEdit::singleline(&mut port).desired_width(80.0))
                        .changed()
                    {
                        if let Ok(p) = port.parse::<u16>() {
                            self.draft_config.tcp_port = p;
                        }
                    }
                });

                ui.add_space(10.0);
                ui.label(RichText::new("Безопасность").strong());
                ui.checkbox(
                    &mut self.draft_config.lan_only,
                    "Только локальная сеть (отклонять адреса вне RFC1918)",
                )
                .on_hover_text(
                    "Защищает от случайного проброса порта в интернет. \
                     Выключайте только осознанно.",
                );
                ui.checkbox(
                    &mut self.draft_config.allow_new_pairings,
                    "Разрешать сопряжение с новыми устройствами",
                )
                .on_hover_text(
                    "Если выключить, подключиться смогут только уже сопряжённые устройства.",
                );
                ui.checkbox(
                    &mut self.draft_config.accept_incoming,
                    "Принимать входящие подключения",
                );
                ui.checkbox(
                    &mut self.draft_config.discovery_enabled,
                    "Объявлять себя в сети (UDP-обнаружение)",
                )
                .on_hover_text(
                    "Отключите, если не хотите, чтобы имя устройства было видно всем в сети.",
                );
                ui.horizontal(|ui| {
                    ui.label("Максимальный размер входящего файла:");
                    let mut gb =
                        (self.draft_config.max_file_size / (1024 * 1024 * 1024)).to_string();
                    if ui
                        .add(egui::TextEdit::singleline(&mut gb).desired_width(60.0))
                        .changed()
                    {
                        if let Ok(v) = gb.parse::<u64>() {
                            self.draft_config.max_file_size = v * 1024 * 1024 * 1024;
                        }
                    }
                    ui.label("ГиБ (0 — без ограничения)");
                });

                ui.add_space(10.0);
                ui.label(RichText::new("Хранилище").strong());
                ui.label(
                    RichText::new(format!("Профиль: {}", self.paths.root.display()))
                        .color(DIM)
                        .small(),
                );

                ui.add_space(12.0);
                if ui
                    .add(egui::Button::new(RichText::new("Применить").strong()))
                    .clicked()
                {
                    apply = true;
                }
            });
        if apply {
            self.draft_config.device_name =
                syncmob::util::clamp_str(self.draft_config.device_name.trim(), 32);
            if self.draft_config.device_name.is_empty() {
                self.draft_config.device_name = "SyncMob PC".into();
            }
            self.config = self.draft_config.clone();
            self.engine.update_config(self.config.clone());
            self.note("Настройки сохранены", GREEN);
            self.show_settings = false;
        } else {
            self.show_settings = open;
        }
    }
}

/// Open a directory in the system file manager.
///
/// The path always comes from our own download directory, never from the
/// network, and is passed as a separate argument rather than through a shell.
fn open_in_file_manager(dir: &std::path::Path) {
    #[cfg(windows)]
    let _ = std::process::Command::new("explorer").arg(dir).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(dir).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
}

fn stamp_now() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

fn stamp(ms: u64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_millis_opt(ms as i64) {
        chrono::offset::LocalResult::Single(t) => t.format("%H:%M:%S").to_string(),
        _ => stamp_now(),
    }
}
