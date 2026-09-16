# SyncMob

[![CI](https://github.com/SeniorK0tik/Antarloka/actions/workflows/ci.yml/badge.svg)](https://github.com/SeniorK0tik/Antarloka/actions/workflows/ci.yml)

Передача файлов и текстовых сообщений между ПК и Android **внутри локальной
сети**, без облака и без интернета. Весь трафик зашифрован, устройства
аутентифицируют друг друга по долговременным ключам, а первое соединение
подтверждается человеком.

```
SyncMob/
├── desktop/     модуль для ПК   — Rust + egui, цель Windows
├── mobile/      модуль Android  — Kotlin + Jetpack Compose
├── PROTOCOL.md  общая спецификация протокола
└── SECURITY.md  модель угроз и разбор защитных мер
```

Модули независимы и общаются только по протоколу из `PROTOCOL.md`.

---

## Как это выглядит в работе

1. Оба устройства в одной Wi-Fi сети объявляют себя по UDP и видят друг друга в
   списке.
2. Первое соединение требует **сопряжения**: обе стороны показывают один и тот же
   восьмизначный код, оба пользователя его сверяют и подтверждают. Либо телефон
   сканирует QR-код с экрана ПК — тогда ключ приходит вне сети и подмена
   исключена автоматически.
3. После сопряжения ключ сохраняется, и дальше устройства узнают друг друга сами.
4. Можно слать текст и файлы в обе стороны. Входящий файл по умолчанию требует
   подтверждения; его SHA-256 проверяется перед сохранением.

---

## Модуль ПК (`desktop/`)

Rust, GUI на `egui`, один самодостаточный `.exe`.

### Сборка

На Windows:

```powershell
cd desktop
cargo build --release
# .\target\release\syncmob-desktop.exe
```

Кросс-сборка с Linux (нужен `rustup target add x86_64-pc-windows-gnu` и `mingw-w64`):

```bash
cd desktop
cargo build --release --target x86_64-pc-windows-gnu
```

### Тесты

```bash
cd desktop
cargo test                          # всё
cargo test --no-default-features    # только ядро, без GUI-зависимостей
```

`--no-default-features` отключает `egui`/`eframe`/`rfd`, поэтому ядро
(криптография, протокол, сеть, движок) собирается и тестируется на машине без
графической подсистемы.

### Структура

```
desktop/src/
├── security/     идентичность, хранилище ключа, список доверия, отпечатки
├── net/          обнаружение по UDP, рукопожатие Noise, шифрованный транспорт
├── proto.rs      формат сообщений (зеркало Kotlin-версии)
├── engine/       оркестрация: слушатель, сопряжение, передачи
├── config.rs     настройки и расположение файлов профиля
├── app.rs, qr.rs интерфейс (egui) — не содержит сетевой логики
└── main.rs
```

Профиль (ключ, список доверия, настройки) лежит в
`%APPDATA%\SyncMob\SyncMob\data\`. Точный путь показан в настройках приложения.

При первом запуске предлагается задать пароль для защиты приватного ключа.
Пароль нигде не хранится и не восстанавливается; отказаться можно, но интерфейс
будет постоянно предупреждать.

---

## Модуль Android (`mobile/`)

Kotlin + Jetpack Compose, `minSdk 26`, `targetSdk 34`.

### Сборка

Открыть папку `mobile/` в Android Studio (Ladybug или новее) — она подтянет SDK
сама. Либо из командной строки (Gradle wrapper уже в репозитории, нужен только
JDK 17 и Android SDK с platform 34 / build-tools 34):

```bash
cd mobile
./gradlew :app:assembleDebug        # app/build/outputs/apk/debug/app-debug.apk
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleRelease      # с R8: ~3.6 МБ, неподписанный
```

Если Android SDK лежит не в стандартном месте, укажите его через переменную
`ANDROID_HOME` или файл `mobile/local.properties` (`sdk.dir=/путь/к/sdk`).

### Структура

```
mobile/app/src/main/java/org/syncmob/mobile/
├── crypto/       Noise XX (написан по спецификации), идентичность в Android Keystore
├── security/     отпечатки, коды сверки, зашифрованный список доверия
├── proto/        формат сообщений (зеркало Rust-версии), разбор QR-ссылки
├── net/          обнаружение по UDP, рукопожатие и шифрованный транспорт
├── engine/       оркестрация, настройки, приём и отправка файлов
├── service/      foreground-служба, чтобы приём работал в фоне
└── ui/           экраны на Compose
```

Приватный ключ запечатан AES-256-GCM-ключом из Android Keystore (на большинстве
устройств — в TEE или защищённом элементе), на API 28+ с флагом
«использовать только при разблокированном устройстве».

Принятые файлы попадают в `Загрузки/SyncMob` через MediaStore (без запроса
разрешений на хранилище); если MediaStore недоступен — в приватный каталог
приложения.

Приём в фоне обеспечивает foreground-служба с постоянным уведомлением: LAN-приёмник,
работающий незаметно, — ровно то, чего у пользователя быть не должно.

---

## Совместимость модулей

Kotlin-реализация Noise написана вручную, поэтому её соответствие Rust-стороне
проверяется, а не предполагается:

* `desktop/tests/noise_reference.rs` — пошаговая реализация по спецификации,
  проверенная против библиотеки `snow` в обеих ролях; Kotlin — её дословный перевод;
* `mobile/.../CrossImplementationVectorsTest.kt` — тест-векторы примитивов,
  сгенерированные Rust-стороной, зафиксированы в Kotlin-тестах;
* `cargo run --example interop_responder -- 45999` и `interop_initiator` —
  настоящее рукопожатие по сокету с любым клиентом.

Проверено сквозным прогоном: рукопожатие Kotlin ↔ Rust в обе стороны даёт
одинаковый хеш рукопожатия и одинаковый код сверки, шифрованные сообщения
проходят в обе стороны.

---

## Сборка в GitHub Actions

Ничего собирать локально не обязательно — всё делает CI.

`.github/workflows/ci.yml` запускается на каждый push и pull request в `main`:

| Задача | Что делает |
|---|---|
| `desktop · core (Linux)` | `cargo fmt --check`, `clippy -D warnings`, тесты ядра |
| `desktop · Windows build` | тесты ядра и релизный `syncmob-desktop.exe` |
| `mobile · APK + unit tests` | `testDebugUnitTest`, debug- и release-APK |

Готовые файлы лежат во вкладке **Actions** → нужный запуск → **Artifacts**
(`syncmob-desktop-windows`, `syncmob-apk-debug`, отчёт тестов Android).

`.github/workflows/release.yml` срабатывает на тег `v*` (или вручную через
**Run workflow**) и публикует GitHub Release с `syncmob-desktop.exe` и APK:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

Release-APK подписывается, только если в **Settings → Secrets and variables →
Actions** заданы секреты `ANDROID_KEYSTORE_BASE64` (`base64 -w0 release.jks`),
`ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`. Без них
в релиз попадает неподписанный release-APK и устанавливаемый debug-APK.

---

## Порты и сеть

| Порт | Назначение |
|---|---|
| `45820/udp` | обнаружение (broadcast + multicast `239.255.79.20`) |
| `45821/tcp` | защищённый канал |

Оба порта настраиваются. На Windows при первом запуске потребуется разрешить
приложению приём подключений в частной сети. Гостевые Wi-Fi сети часто изолируют
клиентов друг от друга — там обнаружение не сработает, и нужно подключаться по
адресу вручную.

Подробности протокола — `PROTOCOL.md`, разбор защиты — `SECURITY.md`.
