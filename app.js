"use strict";

const CONFIG = window.ARDLOG_CONFIG;
const db = window.supabase.createClient(CONFIG.supabaseUrl, CONFIG.supabaseKey, { auth: { persistSession: false } });
const FILE_BUCKET = "files";
const ROOM_CHANNEL = "room:ardlog";
const PRESENCE_FALLBACK_MS = 2000;
const GENERAL_ROOM = "genel";
const GROUP_STORAGE_KEY = "ardlog-groups-v1";
const INVITE_PATTERN = /^#davet=([0-9a-f-]{36})\.([A-Za-z0-9_-]{43})$/;
const COPY_FEEDBACK_MS = 2000;
const HISTORY_LIMIT = 100;
const GROUP_WINDOW_MS = 5 * 60 * 1000;
const NEAR_BOTTOM_PX = 120;
const MIN_PASSWORD_LENGTH = 6;
const IV_LENGTH = 12;
const KEY_LENGTH = 32;
const TEXTAREA_MAX_HEIGHT_PX = 140;
const EFFECT_DURATION_MS = 4500;
const CONFETTI_COUNT = 90;
const HEART_COUNT = 36;
const USERNAME_PATTERN = /^[\p{L}\p{N}_ .-]{1,24}$/u;
const CONNECTION_FAILED_MESSAGE = "Sunucuya bağlanılamadı.";

const MOBILE_QUERY = window.matchMedia("(max-width: 768px)");
const COARSE_POINTER_QUERY = window.matchMedia("(pointer: coarse)");
const REDUCED_MOTION_QUERY = window.matchMedia("(prefers-reduced-motion: reduce)");

const EFFECTS = {
    none: { icon: "💬", label: "Normal" },
    confetti: { icon: "🎉", label: "Konfeti", screen: true },
    hearts: { icon: "❤️", label: "Kalpler", screen: true },
    shake: { icon: "💥", label: "Sarsıntı" },
    loud: { icon: "📣", label: "Bağır" },
    whisper: { icon: "🤫", label: "Fısıltı" },
    glow: { icon: "✨", label: "Parıltı" },
};
const CONFETTI_COLORS = ["#22e36b", "#5dff95", "#15803d", "#f5f5f5", "#a3ffc2"];
const MATRIX_CHARS = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホ0123456789ARD";
const MATRIX_FONT_PX = 16;
const MATRIX_FRAME_MS = 70;
const MATRIX_FADE = "rgba(18, 18, 18, 0.12)";
const MATRIX_COLOR = "#22e36b";
const MATRIX_RESET_CHANCE = 0.975;
const MATRIX_STATIC_FRAMES = 60;
const HEART_EMOJIS = ["❤️", "💖", "💜", "💙", "🩷"];
const FILE_ICONS = [
    [/\.(png|jpe?g|gif|webp|heic|svg)$/i, "🖼️"],
    [/\.(mp4|mov|mkv|webm|avi)$/i, "🎬"],
    [/\.(mp3|wav|ogg|m4a|flac)$/i, "🎵"],
    [/\.pdf$/i, "📕"],
    [/\.(zip|rar|7z|tar|gz)$/i, "🗜️"],
    [/\.(docx?|txt|md|odt)$/i, "📝"],
];

class AuthError extends Error {}

const state = {
    channel: null,
    presenceReady: false,
    wasDisconnected: false,
    onlineUsers: new Set(),
    username: "",
    cryptoKey: null,
    authToken: "",
    isInChat: false,
    isLeaving: false,
    selectedEffect: "none",
    dragDepth: 0,
    lastAuthor: null,
    lastTime: 0,
    renderQueue: Promise.resolve(),
    shownFileIds: new Set(),
    currentRoom: GENERAL_ROOM,
    rooms: new Map(),
    unread: new Map(),
    pendingInvite: null,
};

const CLIENT_ID = readClientId();

function readClientId() {
    try {
        const existing = localStorage.getItem("ardlog-client-id");
        if (existing) return existing;
        const created = crypto.randomUUID();
        localStorage.setItem("ardlog-client-id", created);
        return created;
    } catch {
        return crypto.randomUUID();
    }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const $ = (id) => document.getElementById(id);

function createElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    // Kullanıcı verisi yalnız textContent ile basılır; HTML olarak yorumlanmaz (XSS koruması).
    if (text !== undefined) element.textContent = text;
    return element;
}

function formatFileSize(bytes) {
    const units = ["B", "KB", "MB", "GB"];
    let size = bytes;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex += 1;
    }
    return `${size.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return "";
    return date.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
}

function usernameHue(name) {
    let hash = 0;
    for (const char of name) hash = (hash * 31 + char.codePointAt(0)) % 360;
    return hash;
}

function fileIcon(name) {
    const match = FILE_ICONS.find(([pattern]) => pattern.test(name));
    return match ? match[1] : "📄";
}

/* ---------- Uçtan uca şifreleme ---------- */

function bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary);
}

function base64ToBytes(base64) {
    return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

function bytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// Şifreden 64 bayt türetilir: ilk yarı AES anahtarı (cihazda kalır), ikinci yarı sunucuya giriş jetonu.
async function deriveKeys(password) {
    const material = await crypto.subtle.importKey("raw", encoder.encode(password.normalize("NFC")), "PBKDF2", false, ["deriveBits"]);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: encoder.encode(`ardlog-v1|${CONFIG.salt}`),
            iterations: CONFIG.kdfIterations,
        },
        material,
        KEY_LENGTH * 2 * 8,
    ));
    const cryptoKey = await crypto.subtle.importKey("raw", bits.slice(0, KEY_LENGTH), "AES-GCM", false, ["encrypt", "decrypt"]);
    return { cryptoKey, authToken: bytesToHex(bits.slice(KEY_LENGTH)) };
}

function toBase64Url(bytes) {
    return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(text) {
    const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
    return base64ToBytes(base64 + "===".slice((base64.length + 3) % 4));
}

function importAesKey(rawBytes) {
    return crypto.subtle.importKey("raw", rawBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

function roomKey(roomId) {
    return state.rooms.get(roomId)?.key;
}

function activeKey() {
    return roomKey(state.currentRoom);
}

async function encryptBytes(bytes, key = activeKey()) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes));
    const output = new Uint8Array(IV_LENGTH + cipher.length);
    output.set(iv);
    output.set(cipher, IV_LENGTH);
    return output;
}

async function decryptBytes(bytes, key = activeKey()) {
    const iv = bytes.subarray(0, IV_LENGTH);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, bytes.subarray(IV_LENGTH)));
}

async function encryptText(text, key = activeKey()) {
    return bytesToBase64(await encryptBytes(encoder.encode(text), key));
}

async function decryptText(base64, key = activeKey()) {
    return decoder.decode(await decryptBytes(base64ToBytes(base64), key));
}

function eventRoom(event) {
    return event.room_id ?? GENERAL_ROOM;
}

async function decryptEvent(event) {
    const key = roomKey(eventRoom(event));
    if (event.type === "message") {
        try {
            const payload = JSON.parse(await decryptText(event.content, key));
            const effect = Object.hasOwn(EFFECTS, payload.e) ? payload.e : "none";
            return { ...event, text: String(payload.t ?? ""), effect };
        } catch {
            return { ...event, text: "🔒 Bu mesaj çözülemedi", effect: "none", locked: true };
        }
    }
    if (event.type === "file") {
        try {
            return { ...event, name: await decryptText(event.file_name, key) };
        } catch {
            return { ...event, name: "🔒 Çözülemeyen dosya", locked: true };
        }
    }
    return event;
}

/* ---------- Sunucu ile iletişim ---------- */

function check({ data, error }) {
    if (error) throw new Error(error.message || CONNECTION_FAILED_MESSAGE);
    return data;
}

// Oda tek bir Supabase hesabıdır; hesabın şifresi oda şifresinden türetilen giriş jetonudur.
async function login(authToken) {
    const { error } = await db.auth.signInWithPassword({ email: CONFIG.roomEmail, password: authToken });
    if (!error) return;
    if (error.status === 400) throw new AuthError("Oda şifresi yanlış.");
    throw new Error(error.status === 429 ? "Çok fazla deneme. Biraz sonra tekrar dene." : CONNECTION_FAILED_MESSAGE);
}

function rowToEvent(row) {
    return {
        type: row.msg_type === "file" ? "file" : "message",
        username: row.username,
        content: row.content,
        file_id: row.file_id,
        file_name: row.file_name,
        file_size: row.file_size,
        room_id: row.room_id,
        timestamp: row.created_at,
    };
}

function describeError(error) {
    return error instanceof TypeError ? CONNECTION_FAILED_MESSAGE : error.message;
}

/* ---------- Giriş ---------- */

function setLoginBusy(busy, label = "Bağlan") {
    const button = $("join-button");
    button.disabled = busy;
    button.classList.toggle("busy", busy);
    button.querySelector(".button-label").textContent = label;
}

function showLoginError(message) {
    $("login-error").textContent = message;
}

function showLoginScreen(errorMessage = "") {
    state.isInChat = false;
    $("chat-screen").classList.add("hidden");
    $("login-screen").classList.remove("hidden");
    setLoginBusy(false);
    showLoginError(errorMessage);
    $("password-input").focus();
}

function showChatScreen() {
    state.isInChat = true;
    $("login-screen").classList.add("hidden");
    $("chat-screen").classList.remove("hidden");
    // Geçmiş, ekran gizliyken yüklendiği için kaydırma ancak görünür olunca işe yarar.
    scrollToBottom();
    setLoginBusy(false);
    if (!COARSE_POINTER_QUERY.matches) $("message-input").focus();
}

function validateLogin(name, password) {
    if (!window.isSecureContext || !window.crypto?.subtle) return "Şifreleme için güvenli bağlantı (https) gerekli.";
    if (!name) return "Kullanıcı adı boş olamaz.";
    if (!USERNAME_PATTERN.test(name)) return "En fazla 24 karakter; harf, rakam, boşluk, nokta, tire ve alt çizgi kullanılabilir.";
    if (password.length < MIN_PASSWORD_LENGTH) return `Oda şifresi en az ${MIN_PASSWORD_LENGTH} karakter olmalı.`;
    return "";
}

async function handleLogin(event) {
    event.preventDefault();
    const name = $("username-input").value.trim();
    const password = $("password-input").value;
    const problem = validateLogin(name, password);
    if (problem) {
        showLoginError(problem);
        return;
    }

    showLoginError("");
    setLoginBusy(true, "Anahtar hazırlanıyor…");
    try {
        const keys = await deriveKeys(password);
        setLoginBusy(true, "Bağlanılıyor…");
        await login(keys.authToken);
        Object.assign(state, keys, { username: name, currentRoom: GENERAL_ROOM });
        state.rooms = new Map([[GENERAL_ROOM, { id: GENERAL_ROOM, name: "Genel", key: keys.cryptoKey }]]);
        $("password-input").value = "";
        await loadGroups();
        renderRoomList();
        updateRoomHeader();
        await startSession();
        await acceptPendingInvite();
    } catch (error) {
        console.error("Giriş başarısız:", error);
        showLoginScreen(describeError(error));
    }
}

/* ---------- Oturum ve WebSocket ---------- */

async function startSession() {
    await Promise.all([loadHistory(), loadFiles()]);
    joinRoom();
}

function joinRoom() {
    const channel = db.channel(ROOM_CHANNEL, { config: { private: true, presence: { key: state.username } } });
    state.channel = channel;
    state.presenceReady = false;
    state.onlineUsers = new Set();
    channel
        .on("presence", { event: "sync" }, handlePresenceSync)
        .on("presence", { event: "join" }, ({ key }) => announcePresence(key, true))
        .on("presence", { event: "leave" }, ({ key }) => announcePresence(key, false))
        .on("postgres_changes", { event: "INSERT", schema: "public", table: "messages" }, ({ new: row }) => handleInsertedRow(row))
        .subscribe((status) => handleChannelStatus(channel, status));
}

async function leaveRoom() {
    const channel = state.channel;
    state.channel = null;
    if (channel) await db.removeChannel(channel);
}

async function handlePresenceSync() {
    if (!state.channel) return;
    const names = Object.keys(state.channel.presenceState());
    if (!state.presenceReady) {
        // Sayfa yenilenince eski oturum bir süre çevrimiçi görünür; aynı cihazın oturumu ismi engellemez.
        const wanted = state.username.toLocaleLowerCase("tr");
        const presence = state.channel.presenceState();
        const takenByOther = names.some((name) => name.toLocaleLowerCase("tr") === wanted
            && presence[name].some((meta) => meta.client_id !== CLIENT_ID));
        if (takenByOther) {
            await leaveRoom();
            showLoginScreen("Bu kullanıcı adı şu an kullanımda.");
            return;
        }
        state.presenceReady = true;
        await state.channel.track({ online_at: new Date().toISOString(), client_id: CLIENT_ID });
        showChatScreen();
    }
    state.onlineUsers = new Set(names);
    updateUserList(names.sort((a, b) => a.localeCompare(b, "tr")));
}

// Yeniden bağlanınca Presence herkesi tekrar "katıldı" bildirir; yalnız gerçek değişiklikleri göster.
function announcePresence(name, joined) {
    if (!state.presenceReady || state.onlineUsers.has(name) === joined) return;
    addMessage({ type: "system", content: `${name} ${joined ? "çevrimiçi oldu" : "çevrimdışı oldu"}` });
}

function handleChannelStatus(channel, status) {
    if (channel !== state.channel || state.isLeaving) return;
    if (status === "SUBSCRIBED") {
        setConnectionStatus("online");
        if (state.wasDisconnected) {
            state.wasDisconnected = false;
            Promise.all([loadHistory(), loadFiles()]).catch((error) => console.error("Yenileme başarısız:", error));
        }
        setTimeout(() => {
            if (!state.presenceReady) handlePresenceSync();
        }, PRESENCE_FALLBACK_MS);
        return;
    }
    if (!state.isInChat) {
        leaveRoom();
        showLoginScreen(CONNECTION_FAILED_MESSAGE);
        return;
    }
    state.wasDisconnected = true;
    setConnectionStatus("reconnecting");
}

function setConnectionStatus(status) {
    const element = $("connection-status");
    element.dataset.state = status;
    element.textContent = status === "online" ? "🔒 Uçtan uca şifreli" : "⟳ Yeniden bağlanıyor…";
}

// Şifre çözme asenkron olduğu için mesajlar sıraları korunarak tek kuyrukta işlenir.
function enqueueServerEvent(data) {
    state.renderQueue = state.renderQueue
        .then(async () => handleServerEvent(await decryptEvent(data)))
        .catch((error) => console.error("Mesaj işlenemedi:", error));
}

// Açık odanın mesajı ekrana gelir; bilinen diğer odalar için okunmamış sayısı artar.
function handleInsertedRow(row) {
    const event = rowToEvent(row);
    const roomId = eventRoom(event);
    if (roomId === state.currentRoom) {
        enqueueServerEvent(event);
    } else if (state.rooms.has(roomId)) {
        state.unread.set(roomId, (state.unread.get(roomId) || 0) + 1);
        renderRoomList();
    }
}

function handleServerEvent(event) {
    if (event.room_id !== undefined && eventRoom(event) !== state.currentRoom) return;
    if (event.type === "system") updateUserList(event.users || []);
    if (event.type === "file") updateFileList(event, { prepend: true });
    addMessage(event, { live: true });
}

/* ---------- Mesaj gönderme ---------- */

async function sendMessage(event) {
    event?.preventDefault();
    const input = $("message-input");
    const text = input.value.trim();
    if (!text) return;
    const content = await encryptText(JSON.stringify({ t: text, e: state.selectedEffect }));
    input.value = "";
    autoResize(input);
    selectEffect("none");
    const { error } = await db.from("messages").insert({ username: state.username, content, msg_type: "text", room_id: dbRoomId(state.currentRoom) });
    if (error) {
        console.error("Mesaj gönderilemedi:", error);
        addLocalNotice("Mesaj gönderilemedi, bağlantını kontrol et.");
        input.value = text;
    }
}

async function uploadFile(file) {
    if (file.size > CONFIG.maxFileSize) {
        addLocalNotice(`"${file.name}" ${formatFileSize(CONFIG.maxFileSize)} sınırını aşıyor.`);
        return;
    }
    const button = $("file-button");
    button.disabled = true;
    button.textContent = "⏳";
    try {
        // Yükleme sürerken oda değişebilir; oda ve anahtar baştan sabitlenir.
        const roomId = state.currentRoom;
        const key = activeKey();
        const encrypted = await encryptBytes(new Uint8Array(await file.arrayBuffer()), key);
        const fileId = crypto.randomUUID();
        check(await db.storage.from(FILE_BUCKET).upload(fileId, new Blob([encrypted]), { contentType: "application/octet-stream" }));
        check(await db.from("messages").insert({
            username: state.username,
            msg_type: "file",
            file_id: fileId,
            file_name: await encryptText(file.name, key),
            file_size: file.size,
            room_id: dbRoomId(roomId),
        }));
    } catch (error) {
        console.error("Yükleme hatası:", error);
        addLocalNotice(`"${file.name}" yüklenemedi: ${describeError(error)}`);
    } finally {
        button.disabled = false;
        button.textContent = "📎";
    }
}

async function uploadFiles(files) {
    for (const file of files) {
        await uploadFile(file);
    }
}

async function downloadFile(file, button) {
    const label = button.textContent;
    button.disabled = true;
    button.textContent = "…";
    try {
        const blob = check(await db.storage.from(FILE_BUCKET).download(file.file_id));
        const plain = await decryptBytes(new Uint8Array(await blob.arrayBuffer()), roomKey(eventRoom(file)));
        const url = URL.createObjectURL(new Blob([plain]));
        const link = createElement("a");
        link.href = url;
        link.download = file.name;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (error) {
        console.error("İndirme hatası:", error);
        addLocalNotice(`"${file.name}" indirilemedi: ${describeError(error)}`);
    } finally {
        button.disabled = false;
        button.textContent = label;
    }
}

/* ---------- Geçmiş ve kenar çubuğu ---------- */

async function loadHistory() {
    // Yükleme sürerken oda değişirse eski odanın sonucu ekrana yazılmaz.
    const roomId = state.currentRoom;
    const rows = check(await inCurrentRoom(db.from("messages").select("*")).order("id", { ascending: false }).limit(HISTORY_LIMIT));
    const events = await Promise.all(rows.reverse().map((row) => decryptEvent(rowToEvent(row))));
    if (roomId !== state.currentRoom) return;
    $("message-list").replaceChildren();
    state.lastAuthor = null;
    if (!events.length) showEmptyState();
    events.forEach((event) => addMessage(event, { live: false }));
    scrollToBottom();
}

async function loadFiles() {
    const roomId = state.currentRoom;
    const rows = check(await inCurrentRoom(db.from("messages").select("*")).eq("msg_type", "file").order("id", { ascending: false }));
    const files = await Promise.all(rows.map((row) => decryptEvent(rowToEvent(row))));
    if (roomId !== state.currentRoom) return;
    $("file-list").replaceChildren();
    state.shownFileIds.clear();
    files.forEach((file) => updateFileList(file));
    if (!files.length) $("file-list").appendChild(createElement("li", "empty-note", "Henüz dosya paylaşılmadı."));
}

function createAvatar(name, ghost = false) {
    const avatar = createElement("span", `avatar${ghost ? " ghost" : ""}`, [...name][0].toUpperCase());
    avatar.style.setProperty("--hue", usernameHue(name));
    avatar.setAttribute("aria-hidden", "true");
    return avatar;
}

function updateUserList(users) {
    const list = $("user-list");
    list.replaceChildren();
    users.forEach((name) => {
        const item = createElement("li", "user-item");
        item.append(createAvatar(name), createElement("span", "", name));
        if (name === state.username) item.appendChild(createElement("span", "you-label", "(sen)"));
        list.appendChild(item);
    });
    $("user-count").textContent = `${users.length} çevrimiçi`;
}

function createDownloadButton(file) {
    const button = createElement("button", "download-button", "İndir");
    button.type = "button";
    button.disabled = Boolean(file.locked);
    button.setAttribute("aria-label", `${file.name} dosyasını indir`);
    button.addEventListener("click", () => downloadFile(file, button));
    return button;
}

function createFileInfo(file, detail) {
    const info = createElement("div", "file-info");
    info.append(createElement("span", "file-name", file.name), createElement("span", "file-size", detail));
    info.firstChild.title = file.name;
    return info;
}

function updateFileList(file, { prepend = false } = {}) {
    if (state.shownFileIds.has(file.file_id)) return;
    state.shownFileIds.add(file.file_id);

    const list = $("file-list");
    list.querySelector(".empty-note")?.remove();
    const item = createElement("li", "file-item");
    item.append(
        createElement("span", "file-icon", fileIcon(file.name)),
        createFileInfo(file, `${formatFileSize(file.file_size)} · ${file.username}`),
        createDownloadButton(file),
    );
    if (prepend) list.prepend(item);
    else list.appendChild(item);
}

/* ---------- Mesaj çizimi ---------- */

function showEmptyState() {
    const empty = createElement("div", "empty-state");
    empty.append(createElement("span", "big", "👋"), createElement("strong", "", "Henüz mesaj yok"), createElement("span", "", "İlk mesajı sen gönder!"));
    $("message-list").appendChild(empty);
}

function renderSystemMessage(event) {
    state.lastAuthor = null;
    return createElement("div", "system-message", event.content);
}

function revealWhisper(bubble) {
    bubble.classList.add("revealed");
    bubble.removeAttribute("role");
    bubble.removeAttribute("aria-label");
    bubble.tabIndex = -1;
}

function renderBubble(event) {
    const bubble = createElement("div", `bubble effect-${event.effect}`, event.text);
    if (event.locked) bubble.classList.add("locked");
    if (event.effect === "whisper") {
        bubble.tabIndex = 0;
        bubble.setAttribute("role", "button");
        bubble.setAttribute("aria-label", "Fısıltı mesajı, görmek için dokun");
        bubble.addEventListener("click", () => revealWhisper(bubble));
        bubble.addEventListener("keydown", (keyEvent) => {
            if (keyEvent.key === "Enter" || keyEvent.key === " ") revealWhisper(bubble);
        });
    }
    return bubble;
}

function renderFileCard(event) {
    const card = createElement("div", "file-card");
    card.append(
        createElement("span", "file-icon", fileIcon(event.name)),
        createFileInfo(event, formatFileSize(event.file_size)),
        createDownloadButton(event),
    );
    return card;
}

function replayEffect(bubble, effectId) {
    if (EFFECTS[effectId].screen) {
        playScreenEffect(effectId);
        return;
    }
    const className = effectId === "whisper" ? "revealed" : `effect-${effectId}`;
    bubble.classList.remove(className);
    if (effectId === "whisper") return;
    void bubble.offsetWidth;
    bubble.classList.add(className, "replay");
}

function renderEffectTag(effectId, bubble) {
    const effect = EFFECTS[effectId];
    const tag = createElement("button", "effect-tag", `${effect.icon} ${effect.label}`);
    tag.type = "button";
    tag.title = "Efekti tekrar oynat";
    tag.addEventListener("click", () => replayEffect(bubble, effectId));
    return tag;
}

function renderUserMessage(event) {
    const isOwn = event.username === state.username;
    const time = new Date(event.timestamp).getTime();
    const grouped = state.lastAuthor === event.username && time - state.lastTime < GROUP_WINDOW_MS;
    state.lastAuthor = event.username;
    state.lastTime = time;

    const row = createElement("div", `message ${isOwn ? "own" : "other"}${grouped ? " grouped" : ""}`);
    row.style.setProperty("--hue", usernameHue(event.username));
    if (!isOwn) row.appendChild(createAvatar(event.username, grouped));

    const column = createElement("div", "message-column");
    if (!isOwn && !grouped) column.appendChild(createElement("span", "message-author", event.username));
    const body = event.type === "file" ? renderFileCard(event) : renderBubble(event);
    column.appendChild(body);

    const meta = createElement("div", "message-meta");
    meta.appendChild(createElement("time", "", formatTime(event.timestamp)));
    if (event.effect && event.effect !== "none") meta.appendChild(renderEffectTag(event.effect, body));
    column.appendChild(meta);
    row.appendChild(column);
    return row;
}

function isNearBottom() {
    const list = $("message-list");
    return list.scrollHeight - list.scrollTop - list.clientHeight < NEAR_BOTTOM_PX;
}

function scrollToBottom(smooth = false) {
    const list = $("message-list");
    list.scrollTo({ top: list.scrollHeight, behavior: smooth ? "smooth" : "auto" });
    $("jump-button").classList.add("hidden");
}

function addMessage(event, { live = true } = {}) {
    const list = $("message-list");
    const shouldStick = !live || isNearBottom() || event.username === state.username;
    list.querySelector(".empty-state")?.remove();

    const node = event.type === "system" ? renderSystemMessage(event) : renderUserMessage(event);
    if (!live) node.classList.add("no-animate");
    list.appendChild(node);

    if (live && EFFECTS[event.effect]?.screen) playScreenEffect(event.effect);
    if (shouldStick) scrollToBottom(live);
    else $("jump-button").classList.remove("hidden");
}

function addLocalNotice(text) {
    addMessage({ type: "system", content: text });
}

/* ---------- Ekran efektleri ---------- */

function randomBetween(min, max) {
    return min + Math.random() * (max - min);
}

function createPiece(className, properties) {
    const piece = createElement("span", className);
    Object.entries(properties).forEach(([name, value]) => piece.style.setProperty(name, value));
    return piece;
}

function createConfetti() {
    return Array.from({ length: CONFETTI_COUNT }, () => {
        const piece = createPiece("confetti-piece", {
            "--x": `${randomBetween(0, 100)}vw`,
            "--drift": `${randomBetween(-15, 15)}vw`,
            "--rotate": `${randomBetween(360, 1080)}deg`,
            "--delay": `${randomBetween(0, 0.6)}s`,
            "--duration": `${randomBetween(2.2, 3.6)}s`,
        });
        piece.style.background = CONFETTI_COLORS[Math.floor(Math.random() * CONFETTI_COLORS.length)];
        return piece;
    });
}

function createHearts() {
    return Array.from({ length: HEART_COUNT }, () => {
        const piece = createPiece("heart-piece", {
            "--x": `${randomBetween(0, 96)}vw`,
            "--sway": `${randomBetween(-10, 10)}vw`,
            "--size": `${randomBetween(1, 2.4)}rem`,
            "--delay": `${randomBetween(0, 1.2)}s`,
            "--duration": `${randomBetween(2.5, 3.6)}s`,
        });
        piece.textContent = HEART_EMOJIS[Math.floor(Math.random() * HEART_EMOJIS.length)];
        return piece;
    });
}

function playScreenEffect(effectId) {
    if (REDUCED_MOTION_QUERY.matches) return;
    const pieces = effectId === "confetti" ? createConfetti() : createHearts();
    $("effects-layer").append(...pieces);
    setTimeout(() => pieces.forEach((piece) => piece.remove()), EFFECT_DURATION_MS);
}

/* ---------- Matrix yağmuru ---------- */

function startMatrixRain() {
    const canvas = $("matrix-rain");
    const context = canvas.getContext("2d");
    let drops = [];

    const resize = () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const rows = canvas.height / MATRIX_FONT_PX;
        drops = Array.from({ length: Math.ceil(canvas.width / MATRIX_FONT_PX) }, () => Math.random() * rows);
    };

    const drawFrame = () => {
        context.fillStyle = MATRIX_FADE;
        context.fillRect(0, 0, canvas.width, canvas.height);
        context.fillStyle = MATRIX_COLOR;
        context.font = `${MATRIX_FONT_PX}px monospace`;
        drops.forEach((row, column) => {
            const char = MATRIX_CHARS[Math.floor(Math.random() * MATRIX_CHARS.length)];
            context.fillText(char, column * MATRIX_FONT_PX, row * MATRIX_FONT_PX);
            const offScreen = row * MATRIX_FONT_PX > canvas.height;
            drops[column] = offScreen && Math.random() > MATRIX_RESET_CHANCE ? 0 : row + 1;
        });
    };

    resize();
    window.addEventListener("resize", resize);
    // Hareket azaltma açıksa yağmur akmaz; tek seferlik durağan bir desen çizilir.
    if (REDUCED_MOTION_QUERY.matches) {
        for (let frame = 0; frame < MATRIX_STATIC_FRAMES; frame += 1) drawFrame();
        return;
    }
    let lastFrame = 0;
    const loop = (time) => {
        if (time - lastFrame >= MATRIX_FRAME_MS) {
            drawFrame();
            lastFrame = time;
        }
        requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
}

/* ---------- Efekt menüsü ---------- */

function buildEffectMenu() {
    const menu = $("effect-menu");
    Object.entries(EFFECTS).forEach(([id, effect]) => {
        const option = createElement("button", "effect-option");
        option.type = "button";
        option.dataset.effect = id;
        option.setAttribute("role", "menuitemradio");
        option.setAttribute("aria-checked", String(id === state.selectedEffect));
        option.append(createElement("span", "effect-icon", effect.icon), createElement("span", "", effect.label));
        option.addEventListener("click", () => {
            selectEffect(id);
            toggleEffectMenu(false);
            $("message-input").focus();
        });
        menu.appendChild(option);
    });
}

function selectEffect(id) {
    state.selectedEffect = id;
    const effect = EFFECTS[id];
    $("effect-menu").querySelectorAll(".effect-option").forEach((option) => {
        option.setAttribute("aria-checked", String(option.dataset.effect === id));
    });
    $("effect-chip").classList.toggle("hidden", id === "none");
    $("effect-chip-label").textContent = `${effect.icon} ${effect.label} efektiyle gönderilecek`;
    $("effect-button").classList.toggle("active", id !== "none");
}

function toggleEffectMenu(open) {
    const menu = $("effect-menu");
    const shouldOpen = open ?? menu.classList.contains("hidden");
    menu.classList.toggle("hidden", !shouldOpen);
    $("effect-button").setAttribute("aria-expanded", String(shouldOpen));
    if (shouldOpen) menu.querySelector(`[data-effect="${state.selectedEffect}"]`)?.focus();
}

/* ---------- Gruplar ---------- */

function dbRoomId(roomId) {
    return roomId === GENERAL_ROOM ? null : roomId;
}

function inCurrentRoom(query) {
    return state.currentRoom === GENERAL_ROOM ? query.is("room_id", null) : query.eq("room_id", state.currentRoom);
}

function inviteLink(room) {
    return `${window.location.origin}${window.location.pathname}#davet=${room.id}.${room.rawKey}`;
}

// Grup anahtarları cihazda saklanır ama oda şifresinden türetilen anahtarla şifrelenmiş olarak.
async function saveGroups() {
    const groups = [...state.rooms.values()]
        .filter((room) => room.id !== GENERAL_ROOM)
        .map((room) => ({ id: room.id, key: room.rawKey }));
    try {
        localStorage.setItem(GROUP_STORAGE_KEY, await encryptText(JSON.stringify(groups), roomKey(GENERAL_ROOM)));
    } catch (error) {
        console.warn("Gruplar bu cihaza kaydedilemedi:", error);
    }
}

async function readStoredGroups() {
    try {
        const stored = localStorage.getItem(GROUP_STORAGE_KEY);
        return stored ? JSON.parse(await decryptText(stored, roomKey(GENERAL_ROOM))) : [];
    } catch (error) {
        console.warn("Kayıtlı gruplar okunamadı:", error);
        return [];
    }
}

// Grup satırını çeker ve adını anahtarla çözer; anahtar yanlışsa hata fırlatır.
async function openGroup(id, rawKey) {
    const key = await importAesKey(fromBase64Url(rawKey));
    const rows = check(await db.from("rooms").select("id, name_cipher").eq("id", id));
    if (!rows.length) throw new Error("Grup bulunamadı.");
    const room = { id, rawKey, key, name: await decryptText(rows[0].name_cipher, key) };
    state.rooms.set(id, room);
    return room;
}

async function loadGroups() {
    const stored = await readStoredGroups();
    await Promise.allSettled(stored.map((group) => openGroup(group.id, group.key)));
}

async function createGroup(name) {
    const rawBytes = crypto.getRandomValues(new Uint8Array(KEY_LENGTH));
    const key = await importAesKey(rawBytes);
    const rows = check(await db.from("rooms").insert({ name_cipher: await encryptText(name, key) }).select("id"));
    const room = { id: rows[0].id, rawKey: toBase64Url(rawBytes), key, name };
    state.rooms.set(room.id, room);
    await saveGroups();
    await switchRoom(room.id);
    return room;
}

async function leaveGroup(roomId) {
    state.rooms.delete(roomId);
    state.unread.delete(roomId);
    await saveGroups();
    await switchRoom(GENERAL_ROOM);
}

function readInviteFromUrl() {
    const match = window.location.hash.match(INVITE_PATTERN);
    if (!match) return;
    state.pendingInvite = { id: match[1], rawKey: match[2] };
    // Anahtar adres çubuğunda ve geçmişte kalmasın.
    history.replaceState(null, "", window.location.pathname);
}

async function acceptPendingInvite() {
    const invite = state.pendingInvite;
    state.pendingInvite = null;
    if (!invite) return;
    try {
        const room = state.rooms.get(invite.id) || await openGroup(invite.id, invite.rawKey);
        await saveGroups();
        await switchRoom(room.id);
        addLocalNotice(`"${room.name}" grubuna katıldın.`);
    } catch (error) {
        console.error("Davet açılamadı:", error);
        addLocalNotice("Davet linki geçersiz ya da grup silinmiş.");
    }
}

async function switchRoom(roomId) {
    state.currentRoom = roomId;
    state.unread.delete(roomId);
    renderRoomList();
    updateRoomHeader();
    if (MOBILE_QUERY.matches) setSidebarOpen(false);
    try {
        await Promise.all([loadHistory(), loadFiles()]);
    } catch (error) {
        console.error("Oda yüklenemedi:", error);
        addLocalNotice("Sohbet yüklenemedi, bağlantını kontrol et.");
    }
}

function updateRoomHeader() {
    const room = state.rooms.get(state.currentRoom);
    $("room-title").textContent = room.id === GENERAL_ROOM ? "# Genel" : room.name;
    $("room-menu-button").classList.toggle("hidden", room.id === GENERAL_ROOM);
    document.title = `${room.name} · ArdLog`;
}

function createRoomButton(room) {
    const isActive = room.id === state.currentRoom;
    const button = createElement("button", `room-item${isActive ? " active" : ""}`);
    button.type = "button";
    if (isActive) button.setAttribute("aria-current", "true");
    const icon = createElement("span", "room-icon", room.id === GENERAL_ROOM ? "#" : [...room.name][0].toUpperCase());
    icon.style.setProperty("--hue", usernameHue(room.id));
    button.append(icon, createElement("span", "room-name", room.name));
    const unread = state.unread.get(room.id);
    if (unread) {
        const badge = createElement("span", "unread-badge", unread > 99 ? "99+" : String(unread));
        badge.setAttribute("aria-label", `${unread} okunmamış mesaj`);
        button.appendChild(badge);
    }
    button.addEventListener("click", () => switchRoom(room.id));
    return button;
}

function renderRoomList() {
    const list = $("room-list");
    list.replaceChildren();
    state.rooms.forEach((room) => {
        const item = createElement("li");
        item.appendChild(createRoomButton(room));
        list.appendChild(item);
    });
    const hasUnread = [...state.unread.values()].some((count) => count > 0);
    $("sidebar-toggle").classList.toggle("has-unread", hasUnread);
}

/* ---------- Grup penceresi ---------- */

function setDialogMode(mode, room = null) {
    const isCreate = mode === "create";
    $("group-dialog-title").textContent = isCreate ? "Yeni grup" : room.name;
    $("group-name-field").classList.toggle("hidden", !isCreate);
    $("group-submit").classList.toggle("hidden", !isCreate);
    $("invite-section").classList.toggle("hidden", isCreate);
    $("leave-group").classList.toggle("hidden", isCreate);
    $("share-invite").classList.toggle("hidden", isCreate || !navigator.share);
    $("group-error").textContent = "";
    if (room) $("invite-link").value = inviteLink(room);
}

function openCreateDialog() {
    $("group-name-input").value = "";
    setDialogMode("create");
    $("group-dialog").showModal();
    $("group-name-input").focus();
}

function openInviteDialog() {
    setDialogMode("invite", state.rooms.get(state.currentRoom));
    $("group-dialog").showModal();
}

async function handleCreateGroup(event) {
    event.preventDefault();
    if ($("group-submit").classList.contains("hidden")) return;
    const name = $("group-name-input").value.trim();
    if (!name) {
        $("group-error").textContent = "Grup adı boş olamaz.";
        return;
    }
    const button = $("group-submit");
    button.disabled = true;
    try {
        const room = await createGroup(name);
        setDialogMode("invite", room);
    } catch (error) {
        console.error("Grup oluşturulamadı:", error);
        $("group-error").textContent = `Grup oluşturulamadı: ${describeError(error)}`;
    } finally {
        button.disabled = false;
    }
}

async function copyInviteLink() {
    const button = $("copy-invite");
    try {
        await navigator.clipboard.writeText($("invite-link").value);
        button.textContent = "Kopyalandı ✓";
    } catch {
        $("invite-link").select();
        button.textContent = "Ctrl+C ile kopyala";
    }
    setTimeout(() => {
        button.textContent = "Kopyala";
    }, COPY_FEEDBACK_MS);
}

async function shareInviteLink() {
    const room = state.rooms.get(state.currentRoom);
    try {
        await navigator.share({ title: `ArdLog · ${room.name}`, text: `"${room.name}" grubuna katıl:`, url: $("invite-link").value });
    } catch (error) {
        if (error.name !== "AbortError") console.error("Paylaşılamadı:", error);
    }
}

async function handleLeaveGroup() {
    const room = state.rooms.get(state.currentRoom);
    if (!window.confirm(`"${room.name}" grubundan ayrılmak istiyor musun? Tekrar katılmak için davet linki gerekir.`)) return;
    $("group-dialog").close();
    await leaveGroup(room.id);
}

/* ---------- Kenar çubuğu ---------- */

function setSidebarOpen(open) {
    $("sidebar").classList.toggle("open", open);
    $("sidebar-backdrop").hidden = !open;
    $("sidebar-toggle").setAttribute("aria-expanded", String(open));
    if (open) $("sidebar-close").focus();
    else if (MOBILE_QUERY.matches) $("sidebar-toggle").focus();
}

/* ---------- Olaylar ---------- */

function autoResize(textarea) {
    textarea.style.height = "auto";
    textarea.style.height = `${Math.min(textarea.scrollHeight, TEXTAREA_MAX_HEIGHT_PX)}px`;
}

function setupDragAndDrop() {
    const area = $("chat-area");
    const overlay = $("drop-overlay");
    const hasFiles = (event) => event.dataTransfer?.types.includes("Files");

    area.addEventListener("dragenter", (event) => {
        if (!hasFiles(event)) return;
        event.preventDefault();
        state.dragDepth += 1;
        overlay.classList.remove("hidden");
    });
    area.addEventListener("dragover", (event) => {
        if (hasFiles(event)) event.preventDefault();
    });
    area.addEventListener("dragleave", () => {
        state.dragDepth = Math.max(0, state.dragDepth - 1);
        if (state.dragDepth === 0) overlay.classList.add("hidden");
    });
    area.addEventListener("drop", (event) => {
        event.preventDefault();
        state.dragDepth = 0;
        overlay.classList.add("hidden");
        uploadFiles(Array.from(event.dataTransfer.files));
    });
}

function setupEventListeners() {
    $("login-form").addEventListener("submit", handleLogin);
    $("composer").addEventListener("submit", sendMessage);

    const input = $("message-input");
    input.addEventListener("input", () => autoResize(input));
    input.addEventListener("keydown", (event) => {
        // Dokunmatik klavyede Enter yeni satır açar; gönderme butonla yapılır.
        if (event.key === "Enter" && !event.shiftKey && !event.isComposing && !COARSE_POINTER_QUERY.matches) {
            sendMessage(event);
        }
    });

    $("file-button").addEventListener("click", () => $("file-input").click());
    $("file-input").addEventListener("change", async (event) => {
        await uploadFiles(Array.from(event.target.files));
        event.target.value = "";
    });

    $("effect-button").addEventListener("click", () => toggleEffectMenu());
    $("effect-chip-clear").addEventListener("click", () => selectEffect("none"));
    document.addEventListener("click", (event) => {
        if (!event.target.closest(".effect-wrapper")) toggleEffectMenu(false);
    });

    $("sidebar-toggle").addEventListener("click", () => setSidebarOpen(!$("sidebar").classList.contains("open")));
    $("sidebar-close").addEventListener("click", () => setSidebarOpen(false));
    $("sidebar-backdrop").addEventListener("click", () => setSidebarOpen(false));
    document.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") return;
        if (!$("effect-menu").classList.contains("hidden")) toggleEffectMenu(false);
        else if ($("sidebar").classList.contains("open")) setSidebarOpen(false);
    });

    $("new-group-button").addEventListener("click", openCreateDialog);
    $("room-menu-button").addEventListener("click", openInviteDialog);
    $("group-form").addEventListener("submit", handleCreateGroup);
    $("copy-invite").addEventListener("click", copyInviteLink);
    $("share-invite").addEventListener("click", shareInviteLink);
    $("leave-group").addEventListener("click", handleLeaveGroup);
    $("dialog-close").addEventListener("click", () => $("group-dialog").close());
    window.addEventListener("hashchange", () => {
        readInviteFromUrl();
        if (state.isInChat) acceptPendingInvite();
    });

    $("jump-button").addEventListener("click", () => scrollToBottom(true));
    $("message-list").addEventListener("scroll", () => {
        if (isNearBottom()) $("jump-button").classList.add("hidden");
    });

    window.addEventListener("beforeunload", () => {
        state.isLeaving = true;
        leaveRoom();
    });
    setupDragAndDrop();
}

buildEffectMenu();
setupEventListeners();
startMatrixRain();
readInviteFromUrl();
if (state.pendingInvite) showLoginError("Gruba katılmak için önce giriş yap.");
