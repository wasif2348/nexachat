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
    document.querySelector('.brand-text') && (document.querySelector('.brand-text').innerHTML = 'Nexa<em style="font-style:normal;color:var(--ind-l)">Chat</em>');
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

  const isMine  = currentUser && msg.username === currentUser.username;
  const msgDate = msg.created_at ? new Date(msg.created_at).toDateString() : null;

  // ── Date divider ──
  if (msgDate && msgDate !== lastMsgDate) {
    const divider = document.createElement('div');
    divider.className = 'date-divider';
    divider.textContent = formatDateLabel(msg.created_at);
    msgsList.appendChild(divider);
    lastMsgDate = msgDate;
    lastMsgUser = null;
  }

  const grouped = (lastMsgUser === msg.username);
  lastMsgUser = msg.username;

  const wrapper = document.createElement('div');
  wrapper.className = 'msg' + (isMine ? ' mine' : '') + (grouped ? ' grouped' : '');
  wrapper.dataset.msgId = msg.id;

  const time      = formatTime(msg.created_at);
  const initial   = msg.username[0].toUpperCase();
  const color     = msg.avatar_color || '#4f59e8';
  const roleClass = msg.role === 'admin' ? ' role-admin' : '';
  const msgId     = msg.id || ('local-' + Date.now());

  const avatarHtml = grouped
    ? '<div class="msg-avatar-gap"></div>'
    : '<div class="msg-avatar" style="background:' + escapeHTML(color) + '" data-user="' + escapeHTML(msg.username) + '">' + escapeHTML(initial) + '</div>';

  const senderHtml = (!grouped && !isMine)
    ? '<div class="msg-sender' + roleClass + '" data-user="' + escapeHTML(msg.username) + '">' + escapeHTML(msg.username) + '</div>'
    : '';

  const mineActions = isMine ? `
    <button class="msg-action-btn danger" title="Delete" data-action="delete">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
    </button>` : '';

  const receiptHtml = isMine
    ? '<div class="msg-receipt" id="rr-' + msgId + '"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Sent</div>'
    : '';

  wrapper.innerHTML =
    (isMine ? '<div class="msg-avatar-gap"></div>' : avatarHtml) +
    '<div class="msg-content">' +
    senderHtml +
    '<div style="position:relative">' +
    '<div class="msg-actions">' +
    '<button class="msg-action-btn" title="👍" data-action="react" data-emoji="👍">👍</button>' +
    '<button class="msg-action-btn" title="❤️" data-action="react" data-emoji="❤️">❤️</button>' +
    '<button class="msg-action-btn" title="🔥" data-action="react" data-emoji="🔥">🔥</button>' +
    '<button class="msg-action-btn" title="Reply" data-action="reply"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 17H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v5"/><polyline points="9 11 12 14 22 9"/></svg></button>' +
    mineActions +
    '</div>' +
    '<div class="msg-bubble"><div class="msg-text">' + escapeHTML(msg.text) + '</div><div class="msg-meta">' + time + '</div></div>' +
    '</div>' +
    '<div class="msg-reactions" id="rxns-' + msgId + '"></div>' +
    receiptHtml +
    '</div>' +
    (isMine ? avatarHtml : '');

  // Wire toolbar actions
  wrapper.querySelectorAll('[data-action]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const action = btn.dataset.action;
      if (action === 'react') addReaction(msgId, btn.dataset.emoji, wrapper);
      if (action === 'reply') openReplyBar(msg.username, msg.text);
      if (action === 'delete') deleteMessageLocal(wrapper);
    });
  });

  // Avatar / sender → profile
  wrapper.querySelectorAll('[data-user]').forEach(el => {
    el.addEventListener('click', () => showProfile(msg.username, msg.avatar_color, msg.role, msg.bio));
  });

  msgsList.appendChild(wrapper);

  // Mark receipt delivered → read
  if (isMine) {
    setTimeout(() => {
      const rr = document.getElementById('rr-' + msgId);
      if (rr) {
        rr.classList.add('read');
        rr.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-left:-6px"><polyline points="20 6 9 17 4 12"/></svg> Read';
      }
    }, 2200);
  }
}

// ─── Online Users ────────────────────────────────────────────────────────────
function renderOnlineUsers() {
  const unique = dedupeByUserId(onlineUsers);
  onlineCount.textContent = unique.length;
  onlineListEl.innerHTML  = '';
  unique.forEach(u => {
    const li = document.createElement('li');
    li.className = 'online-item';
    li.innerHTML =
      '<div class="online-avatar" style="background:' + escapeHTML(u.avatar_color || '#4f59e8') + '">' + u.username[0].toUpperCase() + '</div>' +
      '<span class="online-name">' + escapeHTML(u.username) + '</span>';
    li.addEventListener('click', () => showProfile(u.username, u.avatar_color, u.role, u.bio));
    onlineListEl.appendChild(li);
  });

  // Also populate members panel (right sidebar)
  const membersList = document.getElementById('membersList');
  const membersCount = document.getElementById('membersPanelCount');
  if (!membersList) return;
  membersCount && (membersCount.textContent = unique.length);
  membersList.innerHTML = '<div class="members-section-label">Online — ' + unique.length + '</div>';
  unique.forEach(u => {
    const item = document.createElement('div');
    item.className = 'member-item';
    item.innerHTML =
      '<div class="member-avatar" style="background:' + escapeHTML(u.avatar_color || '#4f59e8') + '">' +
      u.username[0].toUpperCase() +
      '<span class="member-status-dot"></span></div>' +
      '<span class="member-name">' + escapeHTML(u.username) + '</span>';
    item.addEventListener('click', () => showProfile(u.username, u.avatar_color, u.role, u.bio));
    membersList.appendChild(item);
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
// ─── Reply Bar Close ─────────────────────────────────────────────────────────
const replyBarCloseBtn = $('replyBarClose');
if (replyBarCloseBtn) replyBarCloseBtn.addEventListener('click', closeReplyBar);

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    $('filesModal').classList.remove('open');
    $('profileModal').classList.remove('open');
    searchPanel.classList.remove('open');
    $('emojiPicker').classList.remove('open');
    $('emojiBtn').classList.remove('active');
    closeReplyBar();
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


// ─── Reply Bar ───────────────────────────────────────────────────────────────
let replyContext = null;

function openReplyBar(username, text) {
  replyContext = { username, text };
  const bar = document.getElementById('replyBar');
  if (!bar) return;
  document.getElementById('replyBarWho').textContent = username;
  document.getElementById('replyBarPreview').textContent = ' · ' + text.slice(0, 60);
  bar.classList.add('visible');
  msgInput.focus();
}

function closeReplyBar() {
  replyContext = null;
  const bar = document.getElementById('replyBar');
  if (bar) bar.classList.remove('visible');
}

// ─── Delete Message (local UI only) ─────────────────────────────────────────
function deleteMessageLocal(wrapper) {
  const bubble = wrapper.querySelector('.msg-bubble');
  if (!bubble) return;
  bubble.innerHTML = '<em class="msg-deleted">This message was deleted</em>';
  bubble.style.cssText += ';background:rgba(248,113,113,.04);border-color:rgba(248,113,113,.08);';
  const actions = wrapper.querySelector('.msg-actions');
  if (actions) actions.innerHTML = '';
  const rxns = wrapper.querySelector('.msg-reactions');
  if (rxns) rxns.innerHTML = '';
}

// ─── Reactions (local UI only) ───────────────────────────────────────────────
function addReaction(msgId, emoji, wrapper) {
  const container = wrapper.querySelector('.msg-reactions');
  if (!container) return;
  const existing = [...container.querySelectorAll('.rxn-chip')].find(c =>
    c.querySelector('span:first-child') && c.querySelector('span:first-child').textContent === emoji
  );
  if (existing) {
    const cnt = existing.querySelector('.rxn-count');
    const n = parseInt(cnt.textContent) || 1;
    if (existing.classList.contains('mine')) {
      if (n <= 1) { existing.remove(); return; }
      cnt.textContent = n - 1;
      existing.classList.remove('mine');
    } else {
      cnt.textContent = n + 1;
      existing.classList.add('mine');
    }
  } else {
    const chip = document.createElement('div');
    chip.className = 'rxn-chip mine';
    chip.innerHTML = '<span>' + emoji + '</span><span class="rxn-count">1</span>';
    chip.addEventListener('click', () => addReaction(msgId, emoji, wrapper));
    container.appendChild(chip);
  }
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
init();
