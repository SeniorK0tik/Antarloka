package org.syncmob.mobile.ui

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.syncmob.mobile.EngineHolder
import org.syncmob.mobile.engine.Engine
import org.syncmob.mobile.engine.Settings
import org.syncmob.mobile.service.SyncMobService
import org.syncmob.mobile.util.SafeFiles
import java.net.InetSocketAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SyncMobService.start(this)

        val shared = extractSharedPayload(intent)

        setContent {
            SyncMobTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val engine = remember { EngineHolder.getOrCreate(this) }
                    if (engine == null) {
                        FatalScreen(EngineHolder.initError ?: "Неизвестная ошибка") {
                            EngineHolder.resetIdentity(this)
                            recreate()
                        }
                    } else {
                        AppRoot(engine, shared)
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }

    /** Files or text handed to us through the system share sheet. */
    private fun extractSharedPayload(intent: Intent?): SharedPayload? {
        if (intent == null) return null
        return when (intent.action) {
            Intent.ACTION_SEND -> {
                val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri
                }
                val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                when {
                    uri != null -> SharedPayload(listOf(uri), null)
                    !text.isNullOrBlank() -> SharedPayload(emptyList(), text)
                    else -> null
                }
            }

            Intent.ACTION_SEND_MULTIPLE -> {
                val uris = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)
                }
                if (uris.isNullOrEmpty()) null else SharedPayload(uris.toList(), null)
            }

            else -> null
        }
    }
}

data class SharedPayload(val uris: List<Uri>, val text: String?)

private sealed class Screen {
    object Devices : Screen()
    data class Chat(val deviceId: String) : Screen()
    object SettingsScreen : Screen()
    object IdentityScreen : Screen()
}

@Composable
private fun FatalScreen(message: String, onReset: () -> Unit) {
    var confirming by remember { mutableStateOf(false) }
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("SyncMob не может запуститься", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(12.dp))
        Text(message, textAlign = TextAlign.Center, color = Amber)
        Spacer(Modifier.height(24.dp))
        Text(
            "Сброс создаст новый ключ устройства. Все сопряжения придётся пройти заново, " +
                "а старые доверенные устройства перестанут вас узнавать.",
            style = MaterialTheme.typography.bodySmall,
            color = Dim,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = { confirming = true }) { Text("Сбросить личность устройства") }
    }
    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text("Сбросить ключ?") },
            text = { Text("Это необратимо. Все сопряжённые устройства придётся сопрягать заново.") },
            confirmButton = {
                TextButton(onClick = { confirming = false; onReset() }) { Text("Сбросить") }
            },
            dismissButton = { TextButton(onClick = { confirming = false }) { Text("Отмена") } },
        )
    }
}

@Composable
private fun AppRoot(engine: Engine, shared: SharedPayload?) {
    val state by engine.state.collectAsStateWithLifecycle()
    var screen by remember { mutableStateOf<Screen>(Screen.Devices) }
    var pendingShare by remember { mutableStateOf(shared) }

    val notificationsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { }
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationsLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    when (val s = screen) {
        is Screen.Devices -> DevicesScreen(
            engine = engine,
            state = state,
            pendingShare = pendingShare,
            onOpenChat = { screen = Screen.Chat(it) },
            onOpenSettings = { screen = Screen.SettingsScreen },
            onOpenIdentity = { screen = Screen.IdentityScreen },
            onShareConsumed = { pendingShare = null },
        )

        is Screen.Chat -> ChatScreen(
            engine = engine,
            state = state,
            deviceId = s.deviceId,
            onBack = { screen = Screen.Devices },
        )

        Screen.SettingsScreen -> SettingsScreen(
            engine = engine,
            state = state,
            onBack = { screen = Screen.Devices },
        )

        Screen.IdentityScreen -> IdentityScreen(
            state = state,
            onBack = { screen = Screen.Devices },
        )
    }

    // Both prompts are modal on purpose: pairing and accepting a file are the
    // two moments where a wrong tap has real consequences.
    state.pairPrompt?.let { PairingDialog(engine, it) }
    state.offerPrompt?.let { OfferDialog(engine, it) }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DevicesScreen(
    engine: Engine,
    state: Engine.State,
    pendingShare: SharedPayload?,
    onOpenChat: (String) -> Unit,
    onOpenSettings: () -> Unit,
    onOpenIdentity: () -> Unit,
    onShareConsumed: () -> Unit,
) {
    var manualHost by remember { mutableStateOf("") }
    var showManual by remember { mutableStateOf(false) }

    val scanner = rememberLauncherForActivityResult(ScanContract()) { result ->
        val contents = result.contents
        if (!contents.isNullOrBlank()) engine.dialPairingUri(contents)
    }
    val cameraPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            scanner.launch(
                ScanOptions()
                    .setPrompt("Наведите камеру на QR-код на экране ПК")
                    .setBeepEnabled(false)
                    .setOrientationLocked(false)
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE),
            )
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("SyncMob") },
                actions = {
                    IconButton(onClick = onOpenIdentity) {
                        Icon(Icons.Default.Fingerprint, contentDescription = "Отпечаток")
                    }
                    IconButton(onClick = { cameraPermission.launch(Manifest.permission.CAMERA) }) {
                        Icon(Icons.Default.QrCodeScanner, contentDescription = "Сканировать QR")
                    }
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Настройки")
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp),
        ) {
            item {
                Spacer(Modifier.height(8.dp))
                Text(
                    "${state.settings.deviceName} • порт ${state.port} • ID ${state.myDeviceId}",
                    style = MaterialTheme.typography.bodySmall,
                    color = Dim,
                )
                if (!state.hardwareBackedKey) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "⚠ Ключ устройства хранится без аппаратной защиты: " +
                            "Android Keystore недоступен на этом устройстве.",
                        style = MaterialTheme.typography.bodySmall,
                        color = Amber,
                    )
                }
                Spacer(Modifier.height(12.dp))
            }

            if (pendingShare != null) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.secondaryContainer,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(Modifier.padding(12.dp)) {
                            val what = if (pendingShare.text != null) {
                                "текст"
                            } else {
                                "${pendingShare.uris.size} файл(ов)"
                            }
                            Text("Готово к отправке: $what", fontWeight = FontWeight.Bold)
                            Text(
                                "Выберите сопряжённое устройство ниже.",
                                style = MaterialTheme.typography.bodySmall,
                            )
                            TextButton(onClick = onShareConsumed) { Text("Отменить") }
                        }
                    }
                    Spacer(Modifier.height(12.dp))
                }
            }

            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedButton(onClick = { showManual = !showManual }) {
                        Text("Подключиться по адресу")
                    }
                    Spacer(Modifier.width(8.dp))
                    IconButton(onClick = { /* state refreshes itself every 2 s */ }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Обновить")
                    }
                }
                if (showManual) {
                    OutlinedTextField(
                        value = manualHost,
                        onValueChange = { manualHost = it },
                        label = { Text("IP[:порт] или syncmob://pair?…") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row {
                        TextButton(onClick = {
                            val v = manualHost.trim()
                            if (v.startsWith("syncmob://")) {
                                engine.dialPairingUri(v)
                            } else {
                                val host = v.substringBefore(':')
                                val port = v.substringAfter(':', "").toIntOrNull()
                                    ?: org.syncmob.mobile.proto.Proto.DEFAULT_TCP_PORT
                                if (host.isNotBlank()) {
                                    engine.dial(InetSocketAddress(host, port), null)
                                }
                            }
                            manualHost = ""
                            showManual = false
                        }) { Text("Связаться") }
                    }
                }
                Spacer(Modifier.height(12.dp))
            }

            if (state.devices.isEmpty()) {
                item {
                    Text(
                        "Устройства не найдены. Убедитесь, что оба устройства в одной Wi-Fi сети, " +
                            "или подключитесь по адресу вручную.",
                        color = Dim,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }

            items(state.devices, key = { it.deviceId }) { device ->
                DeviceCard(
                    device = device,
                    onClick = {
                        if (pendingShare != null && device.connected) {
                            pendingShare.text?.let { engine.sendText(device.deviceId, it) }
                            pendingShare.uris.forEach { engine.sendFile(device.deviceId, it) }
                            onShareConsumed()
                        }
                        onOpenChat(device.deviceId)
                    },
                    onConnect = { engine.connect(device.deviceId) },
                    onDisconnect = { engine.disconnect(device.deviceId) },
                )
                Spacer(Modifier.height(8.dp))
            }

            if (state.transfers.isNotEmpty()) {
                item {
                    Spacer(Modifier.height(16.dp))
                    Text("Передачи", fontWeight = FontWeight.Bold)
                }
                items(state.transfers, key = { it.id + it.finished }) { t ->
                    TransferRow(t) { engine.cancelTransfer(t.id) }
                }
                item {
                    TextButton(onClick = { engine.clearFinishedTransfers() }) {
                        Text("Очистить журнал")
                    }
                }
            }

            item {
                Spacer(Modifier.height(16.dp))
                Text("Журнал", fontWeight = FontWeight.Bold)
            }
            items(state.log.asReversed().take(40)) { line ->
                Text(
                    "${formatTime(line.ts)}  ${line.text}",
                    style = MaterialTheme.typography.bodySmall,
                    color = when (line.level) {
                        Engine.LogLine.Level.GOOD -> Green
                        Engine.LogLine.Level.WARN -> Amber
                        Engine.LogLine.Level.ERROR -> Red
                        else -> Dim
                    },
                )
            }
            item { Spacer(Modifier.height(24.dp)) }
        }
    }
}

@Composable
private fun DeviceCard(
    device: Engine.DeviceView,
    onClick: () -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Row(
            modifier = Modifier.padding(12.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .size(10.dp)
                    .background(
                        when {
                            device.blocked -> Red
                            device.connected -> Green
                            device.online -> Amber
                            else -> Dim
                        },
                        CircleShape,
                    ),
            )
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(device.name, fontWeight = FontWeight.Bold)
                Text(
                    buildString {
                        append(if (device.paired) "сопряжено" else "не сопряжено")
                        if (device.blocked) append(" • заблокировано")
                        device.address?.let { append(" • $it") }
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = Dim,
                )
            }
            if (device.connected) {
                TextButton(onClick = onDisconnect) { Text("Отключить") }
            } else if (device.online && !device.blocked) {
                TextButton(onClick = onConnect) {
                    Text(if (device.paired) "Подключить" else "Сопрячь")
                }
            }
        }
    }
}

@Composable
private fun TransferRow(t: Engine.TransferView, onCancel: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                (if (t.incoming) "↓ " else "↑ ") + t.name,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium,
                color = when {
                    t.error != null -> Red
                    t.finished -> Green
                    else -> MaterialTheme.colorScheme.onSurface
                },
            )
            if (!t.finished) {
                TextButton(onClick = onCancel) { Text("Отмена") }
            }
        }
        if (!t.finished) {
            LinearProgressIndicator(
                progress = { if (t.size == 0L) 0f else t.done.toFloat() / t.size.toFloat() },
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                "${SafeFiles.humanBytes(t.done)} / ${SafeFiles.humanBytes(t.size)}",
                style = MaterialTheme.typography.bodySmall,
                color = Dim,
            )
        } else {
            val detail = t.error ?: t.savedTo?.let { "сохранено в $it" } ?: "готово"
            Text(detail, style = MaterialTheme.typography.bodySmall, color = Dim)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ChatScreen(engine: Engine, state: Engine.State, deviceId: String, onBack: () -> Unit) {
    val device = state.devices.firstOrNull { it.deviceId == deviceId }
    val messages = state.chats[deviceId].orEmpty()
    var draft by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    val filePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments(),
    ) { uris -> uris.forEach { engine.sendFile(deviceId, it) } }

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(device?.name ?: deviceId) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Назад")
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).imePadding()) {
            if (device != null) {
                Column(Modifier.padding(horizontal = 16.dp)) {
                    Text(
                        "Отпечаток: ${device.fingerprint}",
                        style = MaterialTheme.typography.bodySmall,
                        color = Dim,
                        fontFamily = FontFamily.Monospace,
                    )
                    if (device.paired) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Switch(
                                checked = device.autoAccept,
                                onCheckedChange = { engine.setAutoAccept(deviceId, it) },
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                "Принимать файлы без подтверждения",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        Row {
                            TextButton(onClick = { engine.setBlocked(deviceId, !device.blocked) }) {
                                Text(if (device.blocked) "Разблокировать" else "Заблокировать")
                            }
                            TextButton(onClick = { engine.forget(deviceId); onBack() }) {
                                Text("Забыть", color = Red)
                            }
                        }
                    }
                }
                HorizontalDivider()
            }

            LazyColumn(
                state = listState,
                modifier = Modifier.weight(1f).fillMaxWidth().padding(horizontal = 16.dp),
            ) {
                if (messages.isEmpty()) {
                    item {
                        Spacer(Modifier.height(16.dp))
                        Text("Сообщений пока нет", color = Dim)
                    }
                }
                items(messages.size) { index ->
                    val m = messages[index]
                    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                        Text(
                            "${formatTime(m.ts)}  ${if (m.mine) "Вы" else device?.name ?: ""}",
                            style = MaterialTheme.typography.labelSmall,
                            color = Dim,
                        )
                        Surface(
                            color = if (m.system) {
                                MaterialTheme.colorScheme.surfaceVariant
                            } else if (m.mine) {
                                MaterialTheme.colorScheme.primaryContainer
                            } else {
                                MaterialTheme.colorScheme.surface
                            },
                            shape = RoundedCornerShape(10.dp),
                        ) {
                            Text(m.text, modifier = Modifier.padding(10.dp))
                        }
                    }
                }
            }

            val canSend = device?.connected == true
            Row(
                Modifier.fillMaxWidth().padding(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    modifier = Modifier.weight(1f),
                    enabled = canSend,
                    placeholder = { Text("Сообщение…") },
                    maxLines = 4,
                )
                IconButton(
                    onClick = { filePicker.launch(arrayOf("*/*")) },
                    enabled = canSend,
                ) { Icon(Icons.Default.AttachFile, contentDescription = "Файл") }
                IconButton(
                    onClick = {
                        engine.sendText(deviceId, draft)
                        draft = ""
                    },
                    enabled = canSend && draft.isNotBlank(),
                ) { Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Отправить") }
            }
            if (!canSend) {
                Text(
                    "Подключитесь к устройству, чтобы отправлять сообщения и файлы.",
                    Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = Dim,
                )
            }
        }
    }
}

@Composable
private fun PairingDialog(engine: Engine, prompt: Engine.PairPrompt) {
    AlertDialog(
        onDismissRequest = { },
        title = { Text("Подтверждение сопряжения") },
        text = {
            Column {
                Text(
                    if (prompt.remoteInitiated) {
                        "Устройство «${prompt.name.ifEmpty { prompt.deviceId }}» " +
                            "(${prompt.address}) хочет установить связь."
                    } else {
                        "Вы подключаетесь к «${prompt.name.ifEmpty { prompt.deviceId }}» " +
                            "(${prompt.address})."
                    },
                )
                Spacer(Modifier.height(16.dp))
                Text("Код сверки", fontWeight = FontWeight.Bold)
                Text(
                    prompt.sas,
                    fontSize = 32.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Green,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Убедитесь, что на втором устройстве показан ровно такой же код. " +
                        "Если коды различаются — соединение перехвачено, нажмите «Отклонить».",
                    color = Amber,
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(12.dp))
                Text("Отпечаток ключа собеседника", style = MaterialTheme.typography.labelSmall)
                Text(
                    prompt.fingerprint,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        confirmButton = {
            Button(onClick = { engine.respondPairing(prompt.deviceId, true) }) {
                Text("Подтвердить")
            }
        },
        dismissButton = {
            TextButton(onClick = { engine.respondPairing(prompt.deviceId, false) }) {
                Text("Отклонить")
            }
        },
    )
}

@Composable
private fun OfferDialog(engine: Engine, prompt: Engine.OfferPrompt) {
    AlertDialog(
        onDismissRequest = { },
        title = { Text("Входящий файл") },
        text = {
            Column {
                Text("Устройство «${prompt.fromName}» предлагает файл:")
                Spacer(Modifier.height(8.dp))
                Text(prompt.name, fontWeight = FontWeight.Bold)
                Text(SafeFiles.humanBytes(prompt.size), color = Dim)
            }
        },
        confirmButton = {
            Button(onClick = { engine.respondOffer(prompt.transferId, true) }) { Text("Принять") }
        },
        dismissButton = {
            TextButton(onClick = { engine.respondOffer(prompt.transferId, false) }) {
                Text("Отклонить")
            }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsScreen(engine: Engine, state: Engine.State, onBack: () -> Unit) {
    var draft by remember { mutableStateOf(state.settings) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Настройки") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Назад")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(16.dp),
        ) {
            OutlinedTextField(
                value = draft.deviceName,
                onValueChange = { draft = draft.copy(deviceName = it) },
                label = { Text("Имя устройства") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = draft.tcpPort.toString(),
                onValueChange = { v -> v.toIntOrNull()?.let { draft = draft.copy(tcpPort = it) } },
                label = { Text("TCP-порт (применится после перезапуска)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(16.dp))
            Text("Безопасность", fontWeight = FontWeight.Bold)
            SettingSwitch(
                "Только локальная сеть",
                "Отклонять адреса вне частных диапазонов. Выключайте только осознанно.",
                draft.lanOnly,
            ) { draft = draft.copy(lanOnly = it) }
            SettingSwitch(
                "Разрешать новые сопряжения",
                "Если выключить, подключиться смогут только уже сопряжённые устройства.",
                draft.allowNewPairings,
            ) { draft = draft.copy(allowNewPairings = it) }
            SettingSwitch(
                "Принимать входящие подключения",
                "Выключите, чтобы только самим инициировать связь.",
                draft.acceptIncoming,
            ) { draft = draft.copy(acceptIncoming = it) }
            SettingSwitch(
                "Объявлять себя в сети",
                "Отключите, если не хотите, чтобы имя устройства было видно всем в сети.",
                draft.discoveryEnabled,
            ) { draft = draft.copy(discoveryEnabled = it) }

            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = (draft.maxFileSizeBytes / (1024L * 1024 * 1024)).toString(),
                onValueChange = { v ->
                    v.toLongOrNull()?.let {
                        draft = draft.copy(maxFileSizeBytes = it * 1024L * 1024 * 1024)
                    }
                },
                label = { Text("Максимальный размер входящего файла, ГиБ (0 — без лимита)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(Modifier.height(20.dp))
            Button(
                onClick = { engine.updateSettings(draft); onBack() },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Применить") }

            Spacer(Modifier.height(20.dp))
            Text(
                "Приём в фоне обеспечивает служба с постоянным уведомлением. " +
                    "Остановить её можно кнопкой в уведомлении.",
                style = MaterialTheme.typography.bodySmall,
                color = Dim,
            )
        }
    }
}

@Composable
private fun SettingSwitch(
    title: String,
    subtitle: String,
    checked: Boolean,
    onChange: (Boolean) -> Unit,
) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = Dim)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun IdentityScreen(state: Engine.State, onBack: () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Отпечаток устройства") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Назад")
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(16.dp)) {
            Text(
                state.myFingerprint,
                fontFamily = FontFamily.Monospace,
                fontSize = 18.sp,
            )
            Spacer(Modifier.height(8.dp))
            Text("ID: ${state.myDeviceId}", color = Dim)
            Text("Порт: ${state.port}", color = Dim)
            Spacer(Modifier.height(20.dp))
            Text(
                "Этот отпечаток видит собеседник при сопряжении. " +
                    "Он вычисляется из открытого ключа устройства и не является секретом.",
                style = MaterialTheme.typography.bodySmall,
                color = Dim,
            )
            Spacer(Modifier.height(12.dp))
            Text(
                "Закрытый ключ хранится " +
                    if (state.hardwareBackedKey) {
                        "в Android Keystore и не покидает устройство."
                    } else {
                        "в защищённом хранилище приложения (аппаратный Keystore недоступен)."
                    },
                style = MaterialTheme.typography.bodySmall,
                color = if (state.hardwareBackedKey) Dim else Amber,
            )
        }
    }
}

private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

private fun formatTime(ms: Long): String = timeFormat.format(Date(ms))
