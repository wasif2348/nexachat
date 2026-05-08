/* ─── NexaChat — Chat Interface ─────────────────────────────────────────────
 *
 * ⚠️  INTENTIONAL VULNERABILITIES (for ShieldWatch demo):
 *
 *  1. renderSearchResults() — uses innerHTML to render query param
 *     XSS payload: search for <img src=x onerror=alert('XSS')>
 *
 *  2. File viewer (/api/file?path=...) — path not sanitised server-side
 *     Path traversal: browse to ../private/db_config.txt
 *
 * ─────────────────────────────────────────────────────────────────────────── */

// ─── State ────────────────────────────────────────────────────────────────────
let currentUser  = null;
let currentRoom  = null;
let rooms        = [];
let onlineUsers  = [];
const typingUsers = new Set();
let typingTimer   = null;
let isTyping      = false;

// ─── DOM Refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const msgsList        = $('messagesList');
const msgInput        = $('msgInput');
const sendBtn         = $('sendBtn');
const roomListEl      = $('roomList');
const onlineListEl    = $('onlineList');
const onlineCount     = $('onlineCount');
const channelName     = $('channelName');
const channelDesc     = $('channelDesc');
const channelIcon     = $('channelIcon');
const welcomeRoom     = $('welcomeRoom');
const memberCount     = $('memberCount');
const typingBar       = $('typingBar');
const typingText      = $('typingText');
const myAvatar        = $('myAvatar');
const myUsername      = $('myUsername');
const myRole          = $('myRole');
const searchPanel     = $('searchPanel');
const searchInput     = $('searchInput');
const searchResults   = $('searchResults');

// ─── Socket.io ────────────────────────────────────────────────────────────────
const socket = io({ transports: ['websocket', 'polling'] });

socket.on('connect', () => {
  console.log('[Socket] Connected', socket.id);
  if (currentRoom) socket.emit('join_room', currentRoom.id);
});

socket.on('disconnect', () => {
  console.log('[Socket] Disconnected');
});

socket.on('chat_message', (msg) => {
  appendMessage(msg);
  scrollToBottom();
});

socket.on('users_update', (users) => {
  onlineUsers = users;
  renderOnlineUsers();
  renderMemberCount();
});

// ─── Typing Indicators ────────────────────────────────────────────────────────
socket.on('typing_start', ({ username }) => {
  typingUsers.add(username);
  renderTyping();
});

socket.on('typing_stop', ({ username }) => {
  typingUsers.delete(username);
  renderTyping();
});

function renderTyping() {
  const names = Array.from(typingUsers).filter(u => u !== currentUser?.username);
  if (names.length === 0) {
    typingBar.classList.remove('visible');
  } else {
    const label = names.length === 1
      ? `${names[0]} is typing`
      : `${names.slice(0,-1).join(', ')} and ${names[names.length-1]} are typing`;
    typingText.textContent = label;
    typingBar.classList.add('visible');
  }
}

// ─── Bootstrap ────────────────────────────────────────────────────────────────
async function init() {
  try {
    const [meRes, roomsRes] = await Promise.all([
      fetch('/api/me'),
      fetch('/api/rooms')
    ]);

    if (meRes.status === 401) { window.location.href = '/'; return; }

    currentUser = await meRes.json();
    rooms       = await roomsRes.json();

    // Render current user
    myUsername.textContent      = currentUser.username;
    myRole.textContent          = currentUser.role === 'admin' ? '⚑ Admin' : 'Member';
    myAvatar.textContent        = currentUser.username[0].toUpperCase();
    myAvatar.style.background   = currentUser.avatar_color || '#3b82f6';
    myAvatar.style.borderRadius = '10px';

    renderRooms();

    // Auto-join first room
    if (rooms.length > 0) joinRoom(rooms[0]);

  } catch (e) {
    console.error('Init error', e);
    window.location.href = '/';
  }
}

// ─── Render Rooms ─────────────────────────────────────────────────────────────
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

// ─── Join Room ────────────────────────────────────────────────────────────────
async function joinRoom(room) {
  currentRoom = room;

  // Update active state
  document.querySelectorAll('.room-item').forEach(el => {
    el.classList.toggle('active', parseInt(el.dataset.id) === room.id);
  });

  // Update header
  channelName.textContent  = room.name;
  channelDesc.textContent  = room.description || '';
  channelIcon.textContent  = room.icon || '💬';
  welcomeRoom.textContent  = room.name;
  msgInput.placeholder     = `Message #${room.name}`;
  document.title           = `#${room.name} — NexaChat`;

  // Clear messages & typing
  msgsList.innerHTML = '';
  appendWelcome(room);
  typingUsers.clear();
  renderTyping();

  // Tell server
  socket.emit('join_room', room.id);

  // Load history
  try {
    const res  = await fetch(`/api/messages/${room.id}`);
    const msgs = await res.json();
    msgs.forEach(m => appendMessage(m, false));
    scrollToBottom(false);
  } catch (e) {
    console.error('Failed to load messages', e);
  }

  renderMemberCount();
}

// ─── Append Welcome Banner ────────────────────────────────────────────────────
function appendWelcome(room) {
  const div = document.createElement('div');
  div.className = 'messages-welcome';
  div.innerHTML = `
    <div class="welcome-icon">${room.icon || '💬'}</div>
    <div class="welcome-title">Welcome to #${escapeHTML(room.name)}</div>
    <div class="welcome-desc">${escapeHTML(room.description || '')}</div>
  `;
  msgsList.appendChild(div);
}

// ─── Append Message ───────────────────────────────────────────────────────────
let lastMsgUser = null;

function appendMessage(msg, animate = true) {
  const isGrouped = (lastMsgUser === msg.username);
  lastMsgUser = msg.username;

  const div = document.createElement('div');
  div.className = 'msg' + (isGrouped ? ' grouped' : '');
  div.dataset.msgId = msg.id;

  const time = formatTime(msg.created_at);

  if (isGrouped) {
    // Compact continuation
    div.innerHTML = `<div class="msg-body"><div class="msg-text">${escapeHTML(msg.text)}</div></div>`;
  } else {
    const initial    = msg.username[0].toUpperCase();
    const color      = msg.avatar_color || '#3b82f6';
    const roleClass  = msg.role === 'admin' ? ' role-admin' : '';

    div.innerHTML = `
      <div class="msg-avatar" style="background:${escapeHTML(color)}" data-user="${escapeHTML(msg.username)}">${escapeHTML(initial)}</div>
      <div class="msg-body">
        <div class="msg-header">
          <span class="msg-username${roleClass}" data-user="${escapeHTML(msg.username)}">${escapeHTML(msg.username)}</span>
          <span class="msg-time">${time}</span>
        </div>
        <div class="msg-text">${escapeHTML(msg.text)}</div>
      </div>
    `;
  }

  // Avatar / username click → profile
  div.querySelectorAll('[data-user]').forEach(el => {
    el.addEventListener('click', () => showProfile(msg.username, msg.avatar_color, msg.role, msg.bio));
  });

  msgsList.appendChild(div);
}

// ─── Render Online Users ──────────────────────────────────────────────────────
function renderOnlineUsers() {
  const unique = dedupeByUserId(onlineUsers);
  onlineCount.textContent = unique.length;

  onlineListEl.innerHTML = '';
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
  return arr.filter(u => {
    if (seen.has(u.userId)) return false;
    seen.add(u.userId);
    return true;
  });
}

// ─── Send Message ─────────────────────────────────────────────────────────────
function sendMessage() {
  const text = msgInput.value.trim();
  if (!text || !currentRoom) return;

  socket.emit('chat_message', { roomId: currentRoom.id, text });
  msgInput.value = '';

  // Stop typing indicator
  if (isTyping) {
    isTyping = false;
    socket.emit('typing_stop', currentRoom.id);
  }
  clearTimeout(typingTimer);
}

sendBtn.addEventListener('click', sendMessage);
msgInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

// ─── Typing Emit ──────────────────────────────────────────────────────────────
msgInput.addEventListener('input', () => {
  if (!currentRoom) return;

  if (!isTyping) {
    isTyping = true;
    socket.emit('typing_start', currentRoom.id);
  }

  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => {
    isTyping = false;
    socket.emit('typing_stop', currentRoom.id);
  }, 1500);
});

// ─── Scroll to Bottom ─────────────────────────────────────────────────────────
function scrollToBottom(smooth = true) {
  const c = $('messagesContainer');
  const l = msgsList;
  requestAnimationFrame(() => {
    l.scrollTo({ top: l.scrollHeight, behavior: smooth ? 'smooth' : 'instant' });
  });
}

// ─── Sidebar Toggle (mobile) ──────────────────────────────────────────────────
$('sidebarToggle').addEventListener('click', () => {
  $('sidebar').classList.toggle('open');
});

// Click outside sidebar to close on mobile
$('main').addEventListener('click', () => {
  if (window.innerWidth <= 680) $('sidebar').classList.remove('open');
});

// ─── Logout ───────────────────────────────────────────────────────────────────
$('logoutBtn').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = '/';
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  SEARCH — XSS VULNERABLE
//     results.query is reflected from server and inserted via innerHTML
//     Demo: search for <img src=x onerror=alert('ShieldWatch caught it!')>
// ─────────────────────────────────────────────────────────────────────────────
$('searchToggleBtn').addEventListener('click', () => {
  searchPanel.classList.toggle('open');
  if (searchPanel.classList.contains('open')) {
    searchInput.focus();
  }
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

// ─── Jump to message ──────────────────────────────────────────────────────────
function jumpToMsg(id) {
  const el = document.querySelector(`[data-msg-id="${id}"]`);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.style.background = 'rgba(59,130,246,0.1)';
    setTimeout(() => el.style.background = '', 1500);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// FILE SHARING MODAL
// ─────────────────────────────────────────────────────────────────────────────
$('filesBtn').addEventListener('click', openFilesModal);
$('filesClose').addEventListener('click', closeFilesModal);
$('filesModal').addEventListener('click', (e) => { if (e.target === $('filesModal')) closeFilesModal(); });

function openFilesModal() {
  $('filesModal').classList.add('open');
  loadFiles();
}

function closeFilesModal() {
  $('filesModal').classList.remove('open');
  $('fileViewer').classList.remove('open');
}

async function loadFiles() {
  const fileList = $('fileList');
  fileList.innerHTML = '<div class="file-loading">Loading files…</div>';

  try {
    const res   = await fetch('/api/files');
    const files = await res.json();

    fileList.innerHTML = '';

    if (files.length === 0) {
      fileList.innerHTML = '<div class="file-loading">No files available.</div>';
      return;
    }

    files.forEach(name => {
      const item = document.createElement('div');
      item.className = 'file-item';
      item.innerHTML = `
        <span class="file-icon">📄</span>
        <span class="file-name">${escapeHTML(name)}</span>
        <button class="file-view-btn" data-file="${escapeHTML(name)}">View</button>
      `;
      item.querySelector('.file-view-btn').addEventListener('click', () => viewFile(name));
      fileList.appendChild(item);
    });
  } catch (e) {
    fileList.innerHTML = '<div class="file-loading">Failed to load files.</div>';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  FILE VIEWER — PATH TRAVERSAL entry point
//     The `filename` is sent to /api/file?path=<filename>
//     Server does NOT sanitise the path → ../private/db_config.txt works
// ─────────────────────────────────────────────────────────────────────────────
async function viewFile(filename) {
  const viewer    = $('fileViewer');
  const nameEl    = $('viewerFileName');
  const contentEl = $('viewerContent');

  nameEl.textContent    = filename;
  contentEl.textContent = 'Loading…';
  viewer.classList.add('open');

  try {
    const res  = await fetch(`/api/file?path=${encodeURIComponent(filename)}`);
    const data = await res.json();

    if (data.ok) {
      contentEl.textContent = data.content;
    } else {
      contentEl.textContent = `Error: ${data.error}`;
    }
  } catch (e) {
    contentEl.textContent = 'Network error.';
  }
}

$('viewerClose').addEventListener('click', () => $('fileViewer').classList.remove('open'));

// ─── Profile Modal ────────────────────────────────────────────────────────────
$('profileClose').addEventListener('click', () => $('profileModal').classList.remove('open'));
$('profileModal').addEventListener('click', (e) => { if (e.target === $('profileModal')) $('profileModal').classList.remove('open'); });

function showProfile(username, avatarColor, role, bio) {
  const body = $('profileBody');
  body.innerHTML = `
    <div class="profile-card">
      <div class="profile-big-avatar" style="background:${escapeHTML(avatarColor || '#3b82f6')}">${username[0].toUpperCase()}</div>
      <div class="profile-username">${escapeHTML(username)}</div>
      <div class="profile-role">${role === 'admin' ? '⚑ Admin' : 'Member'}</div>
      ${bio ? `<div class="profile-bio">${escapeHTML(bio)}</div>` : ''}
    </div>
  `;
  $('profileModal').classList.add('open');
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// escapeHTML — prevents XSS in all message rendering
// (Note: search results INTENTIONALLY bypass this for demo purposes)
function escapeHTML(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatTime(isoString) {
  if (!isoString) return '';
  const d = new Date(isoString);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ─── Keyboard shortcuts ───────────────────────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    $('filesModal').classList.remove('open');
    $('profileModal').classList.remove('open');
    searchPanel.classList.remove('open');
  }
  // Ctrl+K / Cmd+K to search
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    searchPanel.classList.toggle('open');
    if (searchPanel.classList.contains('open')) searchInput.focus();
  }
});

// ─── Boot ─────────────────────────────────────────────────────────────────────
init();
