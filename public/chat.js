/* ─── NexaChat — Chat Interface ─────────────────────────────────────────────
 *
 * ⚠️  INTENTIONAL VULNERABILITIES (for ShieldWatch demo):
 *
 *  1. renderSearchResults() — uses innerHTML to render data.query raw
 *     XSS payload: search for <img src=x onerror=alert('XSS')>
 *
 *  2. viewFile() — path sent to /api/file?path=<filename> unsanitised
 *     Path traversal: ../private/db_config.txt
 *
 * ─────────────────────────────────────────────────────────────────────────── */

// ─── State ─────────────────────────────────────────────────────────────────
let currentUser  = null;
let currentRoom  = null;
let rooms        = [];
let onlineUsers  = [];
const typingUsers = new Set();
let typingTimer   = null;
let isTyping      = false;
let unreadCount   = 0;        // unread messages while scrolled up
let isAtBottom    = true;     // scroll position tracking

// ─── DOM Refs ───────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const msgsList      = $('messagesList');
const msgInput      = $('msgInput');
const sendBtn       = $('sendBtn');
const roomListEl    = $('roomList');
const onlineListEl  = $('onlineList');
const onlineCount   = $('onlineCount');
const channelName   = $('channelName');
const channelDesc   = $('channelDesc');
const channelIcon   = $('channelIcon');
const welcomeRoom   = $('welcomeRoom');
const memberCount   = $('memberCount');
const typingBar     = $('typingBar');
const typingText    = $('typingText');
const myAvatar      = $('myAvatar');
const myUsername    = $('myUsername');
const myRole        = $('myRole');
const searchPanel   = $('searchPanel');
const searchInput   = $('searchInput');
const searchResults = $('searchResults');
const scrollFab     = $('scrollFab');
const scrollFabBadge = $('scrollFabBadge');
const charCount     = $('charCount');
const swBadge       = $('swBadge');
const swBadgeLabel  = $('swBadgeLabel');

// ─── Socket.io ──────────────────────────────────────────────────────────────
const socket = io({ transports: ['websocket', 'polling'] });

socket.on('connect', () => {
  console.log('[Socket] Connected', socket.id);
  if (currentRoom) socket.emit('join_room', currentRoom.id);
});
socket.on('disconnect', () => console.log('[Socket] Disconnected'));

socket.on('chat_message', (msg) => {
  if (isAtBottom) {
    appendMessage(msg);
    scrollToBottom();
  } else {
    appendMessage(msg);
    unreadCount++;
    scrollFabBadge.textContent = unreadCount > 9 ? '9+' : unreadCount;
    scrollFabBadge.classList.add('show');
  }
});

socket.on('users_update', (users) => {
  onlineUsers = users;
  renderOnlineUsers();
  renderMemberCount();
});

// ─── Typing ─────────────────────────────────────────────────────────────────
socket.on('typing_start', ({ username }) => { typingUsers.add(username);    renderTyping(); });
socket.on('typing_stop',  ({ username }) => { typingUsers.delete(username); renderTyping(); });

function renderTyping() {
  const names = Array.from(typingUsers).filter(u => u !== currentUser?.username);
  if (!names.length) { typingBar.classList.remove('visible'); return; }
  const label = names.length === 1
    ? `${names[0]} is typing`
    : `${names.slice(0,-1).join(', ')} and ${names[names.length-1]} are typing`;
  typingText.textContent = label;
  typingBar.classList.add('visible');
}

// ─── Bootstrap ──────────────────────────────────────────────────────────────
async function init() {
  try {
    const [meRes, roomsRes] = await Promise.all([fetch('/api/me'), fetch('/api/rooms')]);
    if (meRes.status === 401) { window.location.href = '/'; return; }

    currentUser = await meRes.json();
    rooms       = await roomsRes.json();

    myUsername.textContent    = currentUser.username;
    myRole.textContent        = currentUser.role === 'admin' ? '⚑ Admin' : 'Member';
    myAvatar.textContent      = currentUser.username[0].toUpperCase();
    myAvatar.style.background = currentUser.avatar_color || '#3b82f6';
    myAvatar.style.borderRadius = '50%';

    renderRooms();
    if (rooms.length > 0) joinRoom(rooms[0]);

    initScrollTracking();
    initEmojiPicker();
    checkShieldWatchStatus();

  } catch (e) {
    console.error('Init error', e);
    window.location.href = '/';
  }
}

// ─── ShieldWatch Status Badge ────────────────────────────────────────────────
async function checkShieldWatchStatus() {
  try {
    const res  = await fetch('/api/sw/status');
    const data = await res.json();
    if (data.enabled) {
      swBadge.className = 'sw-badge protected';
      swBadgeLabel.textContent = '🛡 Protected';
    } else {
      swBadge.className = 'sw-badge unprotected';
      swBadgeLabel.textContent = '⚠ Unprotected';
    }
  } catch {
    swBadge.className = 'sw-badge';
    swBadgeLabel.textContent = 'SW Offline';
  }
}

// ─── Rooms ──────────────────────────────────────────────────────────────────
function renderRooms() {
  roomListEl.innerHTML = '';
  rooms.forEach(room => {
    const li = document.createElement('li');
    li.className = 'room-item';
    li.dataset.id = room.id;
    li.innerHTML = `
      <span class="room-hash">#</span>
      <span class="room-name">${escapeHTML(room.name)}</span>
    `;
    li.addEventListener('click', () => joinRoom(room));
    roomListEl.appendChild(li);
  });
}

async function joinRoom(room) {
  currentRoom = room;
  lastMsgUser = null;
  lastMsgDate = null;

  document.querySelectorAll('.room-item').forEach(el =>
    el.classList.toggle('active', parseInt(el.dataset.id) === room.id));

  channelName.textContent = room.name;
  channelDesc.textContent = room.description || '';
  channelIcon.textContent = room.icon || '💬';
  welcomeRoom.textContent = room.name;
  msgInput.placeholder    = `Message #${room.name}`;
  document.title          = `#${room.name} — NexaChat`;

  msgsList.innerHTML = '';
  appendWelcome(room);
  typingUsers.clear();
  renderTyping();
  unreadCount = 0;
  scrollFabBadge.classList.remove('show');

  socket.emit('join_room', room.id);

  try {
    const msgs = await (await fetch(`/api/messages/${room.id}`)).json();
    msgs.forEach(m => appendMessage(m, false));
    scrollToBottom(false);
  } catch (e) {
    console.error('Failed to load messages', e);
  }

  renderMemberCount();
}

function appendWelcome(room) {
  const div = document.createElement('div');
  div.className = 'messages-welcome';
  div.innerHTML = `
    <div class="welcome-icon">${room.icon || '💬'}</div>
    <div class="welcome-title">Welcome to #${escapeHTML(room.name)}</div>
    <div class="welcome-desc">${escapeHTML(room.description || 'This is the beginning of the channel.')}</div>
  `;
  msgsList.appendChild(div);
}

// ─── Message Rendering — Chat Bubbles ───────────────────────────────────────
let lastMsgUser = null;
let lastMsgDate = null;

function appendMessage(msg, animate = true) {
  if (!msg || !msg.username) return;

  const isMine    = currentUser && msg.username === currentUser.username;
  const msgDate   = msg.created_at ? new Date(msg.created_at).toDateString() : null;
  const isGrouped = (lastMsgUser === msg.username);

  // ── Date divider ──
  if (msgDate && msgDate !== lastMsgDate) {
    const divider = document.createElement('div');
    divider.className = 'date-divider';
    divider.textContent = formatDateLabel(msg.created_at);
    msgsList.appendChild(divider);
    lastMsgDate = msgDate;
    // Always un-group after a date divider
    lastMsgUser = null;
  }

  const grouped = (lastMsgUser === msg.username);
  lastMsgUser = msg.username;

  const wrapper = document.createElement('div');
  wrapper.className = 'msg' + (isMine ? ' mine' : '') + (grouped ? ' grouped' : '');
  wrapper.dataset.msgId = msg.id;

  const time      = formatTime(msg.created_at);
  const initial   = msg.username[0].toUpperCase();
  const color     = msg.avatar_color || '#3b82f6';
  const roleClass = msg.role === 'admin' ? ' role-admin' : '';

  if (isMine) {
    // ── MY bubble (right) ──
    wrapper.innerHTML = `
      ${grouped ? '<div class="msg-avatar-gap"></div>' : ''}
      <div class="msg-content">
        <div class="msg-bubble">
          <div class="msg-text">${escapeHTML(msg.text)}</div>
          <div class="msg-meta">${time}</div>
        </div>
      </div>
      ${!grouped ? `<div class="msg-avatar" style="background:${escapeHTML(color)}" data-user="${escapeHTML(msg.username)}">${escapeHTML(initial)}</div>` : '<div class="msg-avatar-gap"></div>'}
    `;
  } else {
    // ── THEIR bubble (left) ──
    wrapper.innerHTML = `
      ${!grouped ? `<div class="msg-avatar" style="background:${escapeHTML(color)}" data-user="${escapeHTML(msg.username)}">${escapeHTML(initial)}</div>`
                 : '<div class="msg-avatar-gap"></div>'}
      <div class="msg-content">
        ${!grouped ? `<div class="msg-sender${roleClass}">${escapeHTML(msg.username)}</div>` : ''}
        <div class="msg-bubble">
          <div class="msg-text">${escapeHTML(msg.text)}</div>
          <div class="msg-meta">${time}</div>
        </div>
      </div>
    `;
  }

  // Hover actions toolbar
  const actionsDiv = document.createElement('div');
  actionsDiv.className = 'msg-actions';
  actionsDiv.innerHTML = `
    <button class="msg-action-btn" title="React">👍</button>
    <button class="msg-action-btn" title="React">❤️</button>
    <button class="msg-action-btn" title="React">😂</button>
    <button class="msg-action-btn" title="Reply">↩</button>
  `;
  wrapper.appendChild(actionsDiv);

  // Avatar click → profile
  wrapper.querySelectorAll('[data-user]').forEach(el => {
    el.addEventListener('click', () => showProfile(msg.username, msg.avatar_color, msg.role, msg.bio));
  });

  msgsList.appendChild(wrapper);
}

// ─── Online Users ────────────────────────────────────────────────────────────
function renderOnlineUsers() {
  const unique = dedupeByUserId(onlineUsers);
  onlineCount.textContent = unique.length;
  onlineListEl.innerHTML  = '';
  unique.forEach(u => {
    const li = document.createElement('li');
    li.className = 'online-item';
    li.innerHTML = `
      <div class="online-avatar" style="background:${escapeHTML(u.avatar_color || '#3b82f6')}">${u.username[0].toUpperCase()}</div>
      <span class="online-name">${escapeHTML(u.username)}</span>
    `;
    li.addEventListener('click', () => showProfile(u.username, u.avatar_color, u.role, u.bio));
    onlineListEl.appendChild(li);
  });
}

function renderMemberCount() {
  if (!currentRoom) return;
  const inRoom = onlineUsers.filter(u => u.roomId === currentRoom.id);
  memberCount.textContent = dedupeByUserId(inRoom).length;
}

function dedupeByUserId(arr) {
  const seen = new Set();
  return arr.filter(u => { if (seen.has(u.userId)) return false; seen.add(u.userId); return true; });
}

// ─── Send Message ────────────────────────────────────────────────────────────
function sendMessage() {
  const text = msgInput.value.trim();
  if (!text || !currentRoom) return;
  socket.emit('chat_message', { roomId: currentRoom.id, text });
  msgInput.value = '';
  charCount.textContent = '';
  charCount.className = 'char-count';
  if (isTyping) { isTyping = false; socket.emit('typing_stop', currentRoom.id); }
  clearTimeout(typingTimer);
  isAtBottom = true;
  scrollToBottom();
}

sendBtn.addEventListener('click', sendMessage);
msgInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});

// ─── Typing Emit ─────────────────────────────────────────────────────────────
msgInput.addEventListener('input', () => {
  if (!currentRoom) return;
  // Character counter
  const len = msgInput.value.length;
  if (len > 1500) {
    charCount.textContent = `${len} / 2000`;
    charCount.className   = len > 1900 ? 'char-count limit' : 'char-count warn';
  } else {
    charCount.textContent = '';
    charCount.className   = 'char-count';
  }
  // Typing indicator
  if (!isTyping) { isTyping = true; socket.emit('typing_start', currentRoom.id); }
  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => { isTyping = false; socket.emit('typing_stop', currentRoom.id); }, 1500);
});

// ─── Scroll Tracking + FAB ───────────────────────────────────────────────────
function initScrollTracking() {
  msgsList.addEventListener('scroll', () => {
    const distFromBottom = msgsList.scrollHeight - msgsList.scrollTop - msgsList.clientHeight;
    isAtBottom = distFromBottom < 80;
    if (isAtBottom) {
      unreadCount = 0;
      scrollFabBadge.classList.remove('show');
      scrollFab.classList.remove('visible');
    } else {
      scrollFab.classList.add('visible');
    }
  });

  scrollFab.addEventListener('click', () => {
    unreadCount = 0;
    scrollFabBadge.classList.remove('show');
    scrollFab.classList.remove('visible');
    scrollToBottom();
  });
}

function scrollToBottom(smooth = true) {
  requestAnimationFrame(() => {
    msgsList.scrollTo({ top: msgsList.scrollHeight, behavior: smooth ? 'smooth' : 'instant' });
  });
}

// ─── Sidebar Toggle ───────────────────────────────────────────────────────────
$('sidebarToggle').addEventListener('click', () => $('sidebar').classList.toggle('open'));
$('main').addEventListener('click', () => {
  if (window.innerWidth <= 680) $('sidebar').classList.remove('open');
});

// ─── Logout ───────────────────────────────────────────────────────────────────
$('logoutBtn').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = '/';
});

// ─── Emoji Picker ─────────────────────────────────────────────────────────────
const EMOJIS = [
  '😀','😂','😊','😍','🥰','😎','🤔','😅','😭','😤',
  '🥺','😳','🤩','🥳','😱','😏','🙄','😴','🤯','😇',
  '👍','👎','❤️','🔥','✅','💯','🎉','🙏','👏','💪',
  '🤝','✨','⚡','🚀','🎯','💡','⚠️','🛡️','🔒','🌟',
  '👀','💬','📢','✉️','🔔','💻','📱','🌐','⭐','🎮',
];

function initEmojiPicker() {
  const picker = $('emojiPicker');
  const grid   = $('emojiGrid');

  EMOJIS.forEach(emoji => {
    const btn = document.createElement('button');
    btn.className   = 'emoji-btn-item';
    btn.textContent = emoji;
    btn.addEventListener('click', () => {
      const pos = msgInput.selectionStart;
      const val = msgInput.value;
      msgInput.value = val.slice(0, pos) + emoji + val.slice(pos);
      msgInput.selectionStart = msgInput.selectionEnd = pos + emoji.length;
      msgInput.focus();
    });
    grid.appendChild(btn);
  });

  $('emojiBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    picker.classList.toggle('open');
    $('emojiBtn').classList.toggle('active', picker.classList.contains('open'));
  });

  document.addEventListener('click', (e) => {
    if (!picker.contains(e.target) && e.target !== $('emojiBtn')) {
      picker.classList.remove('open');
      $('emojiBtn').classList.remove('active');
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  SEARCH — XSS VULNERABLE
//     data.query is inserted via innerHTML without escaping
//     Demo payload: <img src=x onerror=alert('ShieldWatch caught it!')>
// ─────────────────────────────────────────────────────────────────────────────
$('searchToggleBtn').addEventListener('click', () => {
  searchPanel.classList.toggle('open');
  if (searchPanel.classList.contains('open')) searchInput.focus();
});
$('clearSearch').addEventListener('click', () => {
  searchInput.value = '';
  searchResults.innerHTML = '';
  searchPanel.classList.remove('open');
});

let searchDebounce = null;
searchInput.addEventListener('input', () => {
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(doSearch, 400);
});

async function doSearch() {
  const q = searchInput.value.trim();
  if (!q || !currentRoom) { searchResults.innerHTML = ''; return; }
  try {
    const res  = await fetch(`/api/search?q=${encodeURIComponent(q)}&roomId=${currentRoom.id}`);
    const data = await res.json();
    renderSearchResults(data);
  } catch (e) {
    searchResults.innerHTML = '<div class="search-no-results">Error searching.</div>';
  }
}

function renderSearchResults(data) {
  if (!data.results || data.results.length === 0) {
    // !! VULNERABLE: data.query inserted via innerHTML — reflects raw server response !!
    searchResults.innerHTML = `<div class="search-no-results">No results for "${data.query}"</div>`;
    return;
  }
  // !! VULNERABLE: data.query in innerHTML below !!
  let html = `<div style="padding:6px 10px;font-size:11px;color:var(--text-muted)">Results for "${data.query}"</div>`;
  data.results.forEach(msg => {
    html += `
      <div class="search-result-item" onclick="jumpToMsg(${msg.id})">
        <div class="search-result-username">${escapeHTML(msg.username)}</div>
        <div class="search-result-text">${escapeHTML(msg.text)}</div>
      </div>
    `;
  });
  searchResults.innerHTML = html;
}

function jumpToMsg(id) {
  const el = document.querySelector(`[data-msg-id="${id}"]`);
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  el.classList.add('highlight');
  setTimeout(() => el.classList.remove('highlight'), 1600);
}

// ─────────────────────────────────────────────────────────────────────────────
// FILE BROWSER — redesigned modal
// ─────────────────────────────────────────────────────────────────────────────
const FILE_ICONS = {
  js:   '🟨', ts: '🟦', json: '📋', html: '🌐', css: '🎨',
  md:   '📝', txt: '📄', sql:  '🗄️', env:  '🔐', py:  '🐍',
  sh:   '⚙️', log: '📜', xml:  '📰', yml:  '⚙️', yaml:'⚙️',
};

function getFileIcon(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  return FILE_ICONS[ext] || '📄';
}

$('filesBtn').addEventListener('click', openFilesModal);
$('filesClose').addEventListener('click', closeFilesModal);
$('filesModal').addEventListener('click', (e) => { if (e.target === $('filesModal')) closeFilesModal(); });

function openFilesModal() {
  $('filesModal').classList.add('open');
  loadFiles();
}
function closeFilesModal() {
  $('filesModal').classList.remove('open');
  $('viewerPane') && ($('viewerContent').textContent = 'Select a file from the list to preview its contents.');
}

async function loadFiles() {
  const fileList = $('fileList');
  fileList.innerHTML = '<div class="file-loading">Loading files…</div>';
  try {
    const files = await (await fetch('/api/files')).json();
    fileList.innerHTML = '';
    if (!files.length) { fileList.innerHTML = '<div class="file-loading">No files found.</div>'; return; }
    files.forEach(name => {
      const item = document.createElement('div');
      item.className = 'file-item';
      const ext = (name.split('.').pop() || '').toUpperCase();
      item.innerHTML = `
        <div class="file-type-icon">${getFileIcon(name)}</div>
        <div class="file-item-info">
          <div class="file-item-name">${escapeHTML(name)}</div>
          <div class="file-item-ext">${ext} file</div>
        </div>
      `;
      item.addEventListener('click', () => {
        document.querySelectorAll('.file-item').forEach(el => el.classList.remove('active'));
        item.classList.add('active');
        viewFile(name);
      });
      fileList.appendChild(item);
    });
  } catch (e) {
    fileList.innerHTML = '<div class="file-loading">Failed to load files.</div>';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  FILE VIEWER — PATH TRAVERSAL entry point
//     filename is sent to /api/file?path=<filename> — NOT sanitised server-side
//     Demo: try ../private/db_config.txt
// ─────────────────────────────────────────────────────────────────────────────
async function viewFile(filename) {
  $('viewerFileName').textContent = filename;
  $('viewerIcon').textContent     = getFileIcon(filename);
  $('viewerContent').textContent  = 'Loading…';

  try {
    const res  = await fetch(`/api/file?path=${encodeURIComponent(filename)}`);
    const data = await res.json();
    $('viewerContent').textContent = data.ok ? data.content : `⚠ Error: ${data.error}`;
  } catch (e) {
    $('viewerContent').textContent = 'Network error.';
  }
}

$('viewerClose').addEventListener('click', () => {
  document.querySelectorAll('.file-item').forEach(el => el.classList.remove('active'));
  $('viewerContent').textContent = 'Select a file from the list to preview its contents.';
  $('viewerFileName').textContent = 'No file selected';
  $('viewerIcon').textContent = '📄';
});

// Custom path input (path traversal demo)
$('customPathBtn').addEventListener('click', () => {
  const p = $('customPath').value.trim();
  if (p) viewFile(p);
});
$('customPath').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { const p = $('customPath').value.trim(); if (p) viewFile(p); }
});

// ─── Profile Modal ────────────────────────────────────────────────────────────
$('profileClose').addEventListener('click',  () => $('profileModal').classList.remove('open'));
$('profileModal').addEventListener('click', (e) => { if (e.target === $('profileModal')) $('profileModal').classList.remove('open'); });

function showProfile(username, avatarColor, role, bio) {
  const body = $('profileBody');
  const isAdmin = role === 'admin';
  body.innerHTML = `
    <div class="profile-card">
      <div class="profile-big-avatar" style="background:${escapeHTML(avatarColor || '#3b82f6')}">${username[0].toUpperCase()}</div>
      <div class="profile-username">${escapeHTML(username)}</div>
      <div class="profile-role-pill${isAdmin ? ' admin' : ''}">${isAdmin ? '⚑ Admin' : 'Member'}</div>
      ${bio ? `<div class="profile-bio">${escapeHTML(bio)}</div>` : ''}
    </div>
  `;
  $('profileModal').classList.add('open');
}

// ─── Keyboard Shortcuts ───────────────────────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    $('filesModal').classList.remove('open');
    $('profileModal').classList.remove('open');
    searchPanel.classList.remove('open');
    $('emojiPicker').classList.remove('open');
    $('emojiBtn').classList.remove('active');
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    searchPanel.classList.toggle('open');
    if (searchPanel.classList.contains('open')) searchInput.focus();
  }
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

// escapeHTML — safe in all message rendering (search intentionally bypasses this)
function escapeHTML(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function formatTime(isoString) {
  if (!isoString) return '';
  return new Date(isoString).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatDateLabel(isoString) {
  if (!isoString) return 'Today';
  const d     = new Date(isoString);
  const today = new Date();
  const yesterday = new Date(today); yesterday.setDate(today.getDate() - 1);
  if (d.toDateString() === today.toDateString())     return 'Today';
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' });
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
init();
