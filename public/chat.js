/* ─── NexaChat — Chat Interface ─────────────────────────────────────────────
 *
 * ⚠️  INTENTIONAL VULNERABILITIES (for ShieldWatch demo — DO NOT FIX):
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
let unreadCount   = 0;
let isAtBottom    = true;
let replyContext  = null;
let slowModeActive = 0;       // seconds for current room
let slowCdTimer   = null;     // interval for countdown
let pinnedMsg     = null;     // { msgId, text, username, pinnedBy }
let isMuted       = false;
let currentPinnedMsgId = null;

// @mention state
let mentionActive   = false;
let mentionStart    = -1;   // index in input where @ begins
let mentionSelected = -1;   // currently highlighted dropdown index

// ─── DOM Refs ───────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const msgsList       = $('messagesList');
const msgInput       = $('msgInput');
const sendBtn        = $('sendBtn');
const roomListEl     = $('roomList');
const onlineListEl   = $('onlineList');
const onlineCount    = $('onlineCount');
const channelName    = $('channelName');
const channelDesc    = $('channelDesc');
const channelIcon    = $('channelIcon');
const welcomeRoom    = $('welcomeRoom');
const memberCount    = $('memberCount');
const typingBar      = $('typingBar');
const typingText     = $('typingText');
const myAvatar       = $('myAvatar');
const myUsername     = $('myUsername');
const myRole         = $('myRole');
const searchPanel    = $('searchPanel');
const searchInput    = $('searchInput');
const searchResults  = $('searchResults');
const scrollFab      = $('scrollFab');
const scrollFabBadge = $('scrollFabBadge');
const charCount      = $('charCount');
const swBadge        = $('swBadge');
const swBadgeLabel   = $('swBadgeLabel');

// ─── Socket.io ──────────────────────────────────────────────────────────────
const socket = io({ transports: ['websocket', 'polling'] });

socket.on('connect', () => {
  console.log('[Socket] Connected', socket.id);
  // BUG FIX #6: On reconnect, re-join room AND re-fetch missed messages
  if (currentRoom) {
    socket.emit('join_room', currentRoom.id);
    fetchMessages(currentRoom.id);
  }
});
socket.on('disconnect', () => console.log('[Socket] Disconnected'));

socket.on('chat_message', (msg) => {
  appendMessage(msg);
  if (isAtBottom) {
    scrollToBottom();
  } else {
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

// ─── Bug Fix #1: Delete broadcast ───────────────────────────────────────────
socket.on('message_deleted', ({ msgId }) => {
  const el = document.querySelector(`[data-msg-id="${msgId}"]`);
  if (!el) return;
  const bubble = el.querySelector('.msg-bubble');
  if (!bubble) return;
  bubble.innerHTML = '<em class="msg-deleted">This message was deleted</em>';
  bubble.style.cssText += ';background:rgba(248,113,113,.04);border-color:rgba(248,113,113,.08);';
  const actions = el.querySelector('.msg-actions');
  if (actions) actions.innerHTML = '';
  const rxns = el.querySelector('.msg-reactions');
  if (rxns) rxns.innerHTML = '';
});

// ─── Bug Fix #2: Reactions broadcast ────────────────────────────────────────
socket.on('reaction_update', ({ msgId, reactions }) => {
  const el = document.querySelector(`[data-msg-id="${msgId}"]`);
  if (!el) return;
  renderReactions(el, msgId, reactions);
});

// ─── Admin Events ────────────────────────────────────────────────────────────
socket.on('kicked', ({ by }) => {
  $('kickedMsg').textContent = `You were removed from the chat by ${escapeHTML(by)}.`;
  $('kickedOverlay').classList.add('show');
});

socket.on('you_are_muted', ({ until, by }) => {
  isMuted = true;
  msgInput.disabled = true;
  msgInput.placeholder = '🔇 You have been muted by admin';
  const label = until === Infinity
    ? 'You have been permanently muted by an admin.'
    : `You have been muted until ${new Date(until).toLocaleTimeString()}.`;
  showToast(label, 'error');
});

socket.on('you_are_unmuted', () => {
  isMuted = false;
  msgInput.disabled = false;
  msgInput.placeholder = currentRoom ? `Message #${currentRoom.name}` : 'Message…';
  showToast('You have been unmuted.', 'success');
});

socket.on('system_message', ({ text }) => {
  appendSystemMessage(text);
});

socket.on('message_pinned', ({ msgId, text, username, pinnedBy }) => {
  currentPinnedMsgId = msgId;
  showPinnedBar({ msgId, text, username, pinnedBy });
});

socket.on('message_unpinned', () => {
  currentPinnedMsgId = null;
  hidePinnedBar();
});

socket.on('slow_mode_update', ({ roomId, seconds }) => {
  if (!currentRoom || currentRoom.id !== roomId) return;
  slowModeActive = seconds;
  updateSlowModeUI();
});

socket.on('global_announcement', ({ text, by }) => {
  showAnnouncementBanner(text, by);
});

socket.on('admin_toast', ({ msg, type }) => {
  showToast(msg, type || 'info');
});

socket.on('message_blocked', ({ error, threat, remainingMs }) => {
  if (threat === 'slowmode' && remainingMs) {
    startSlowCountdown(Math.ceil(remainingMs / 1000));
  } else {
    showToast(error || 'Message blocked by ShieldWatch.', 'error');
  }
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

    // Show admin toolbar
    if (currentUser.role === 'admin') {
      $('adminToolbar').style.display = 'flex';
      document.querySelectorAll('.admin-only-el').forEach(el => el.style.display = '');
    }

    renderRooms();
    if (rooms.length > 0) joinRoom(rooms[0]);

    initScrollTracking();
    initEmojiPicker();
    checkShieldWatchStatus();
    initAdminUI();

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
  closeSidebarOnMobile(); // auto-close sidebar when switching channels on phone

  document.querySelectorAll('.room-item').forEach(el =>
    el.classList.toggle('active', parseInt(el.dataset.id) === room.id));

  channelName.textContent = room.name;
  channelDesc.textContent = room.description || '';
  channelIcon.textContent = room.icon || '💬';
  welcomeRoom.textContent = room.name;
  msgInput.placeholder    = isMuted ? '🔇 You have been muted' : `Message #${room.name}`;
  document.title          = `#${room.name} — NexaChat`;

  msgsList.innerHTML = '';
  appendWelcome(room);
  typingUsers.clear();
  renderTyping();
  unreadCount = 0;
  scrollFabBadge.classList.remove('show');

  // BUG FIX #5: Clear search panel when switching rooms
  searchInput.value = '';
  searchResults.innerHTML = '';
  searchPanel.classList.remove('open');

  // Reset slow mode for new room
  slowModeActive = 0;
  updateSlowModeUI();
  hidePinnedBar();
  currentPinnedMsgId = null;

  // Update slow mode room name in modal
  if ($('slowModeRoomName')) $('slowModeRoomName').textContent = `#${room.name}`;

  socket.emit('join_room', room.id);

  await fetchMessages(room.id);

  // Load pinned message for this room
  loadPinnedMessage(room.id);

  renderMemberCount();
}

async function fetchMessages(roomId) {
  try {
    const msgs = await (await fetch(`/api/messages/${roomId}`)).json();
    if (!Array.isArray(msgs)) return;
    // Clear existing messages (keep welcome banner)
    const welcome = msgsList.querySelector('.messages-welcome');
    msgsList.innerHTML = '';
    if (welcome) msgsList.appendChild(welcome);
    lastMsgUser = null;
    lastMsgDate = null;
    msgs.forEach(m => appendMessage(m, false));
    scrollToBottom(false);
    // Load all reactions for this room in one request
    loadRoomReactions(roomId);
  } catch (e) {
    console.error('Failed to load messages', e);
  }
}

async function loadRoomReactions(roomId) {
  try {
    const res  = await fetch(`/api/reactions/room/${roomId}`);
    const data = await res.json();
    if (!data.reactions) return;
    Object.entries(data.reactions).forEach(([msgId, reactions]) => {
      const el = document.querySelector(`[data-msg-id="${msgId}"]`);
      if (el) renderReactions(el, parseInt(msgId), reactions);
    });
  } catch(e) {}
}

async function loadPinnedMessage(roomId) {
  try {
    const res = await fetch(`/api/pinned/${roomId}`);
    const data = await res.json();
    if (data.pin) {
      currentPinnedMsgId = data.pin.message_id;
      showPinnedBar({
        msgId: data.pin.message_id,
        text: data.pin.message_text,
        username: data.pin.message_username,
        pinnedBy: data.pin.pinned_by,
      });
    }
  } catch(e) {}
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

// ─── Message Rendering ───────────────────────────────────────────────────────
let lastMsgUser = null;
let lastMsgDate = null;

function appendMessage(msg, animate = true) {
  if (!msg || !msg.username) return;

  // Handle deleted messages from REST history
  if (msg.deleted) {
    appendDeletedMessage(msg);
    return;
  }

  const isMine   = currentUser && msg.username === currentUser.username;
  const isAdmin  = currentUser && currentUser.role === 'admin';
  const msgDate  = msg.created_at ? new Date(msg.created_at).toDateString() : null;

  // ── Date divider ──
  if (msgDate && msgDate !== lastMsgDate) {
    const divider = document.createElement('div');
    divider.className = 'date-divider';
    divider.textContent = formatDateLabel(msg.created_at);
    msgsList.appendChild(divider);
    lastMsgDate = msgDate;
    lastMsgUser = null;
  }

  const grouped  = (lastMsgUser === msg.username);
  lastMsgUser    = msg.username;

  const wrapper  = document.createElement('div');
  wrapper.className = 'msg' + (isMine ? ' mine' : '') + (grouped ? ' grouped' : '') + (animate ? '' : ' no-anim');
  wrapper.dataset.msgId = msg.id;

  const time      = formatTime(msg.created_at);
  const initial   = msg.username[0].toUpperCase();
  const color     = msg.avatar_color || '#4f59e8';
  // BUG FIX #4: Use role from msg object (now included in both socket broadcast and REST query)
  const roleClass = (msg.role === 'admin' || msg.user_role === 'admin') ? ' role-admin' : '';
  const msgId     = msg.id;

  const avatarHtml = grouped
    ? '<div class="msg-avatar-gap"></div>'
    : '<div class="msg-avatar" style="background:' + escapeHTML(color) + '" data-user="' + escapeHTML(msg.username) + '">' + escapeHTML(initial) + '</div>';

  const senderHtml = (!grouped && !isMine)
    ? '<div class="msg-sender' + roleClass + '" data-user="' + escapeHTML(msg.username) + '">' + escapeHTML(msg.username) + '</div>'
    : '';

  // BUG FIX #3: Render reply quote if this message is a reply
  const replyHtml = (msg.reply_to_id && msg.reply_to_username)
    ? `<div class="msg-reply-quote" data-jump="${msg.reply_to_id}">
         <div class="reply-quote-who">${escapeHTML(msg.reply_to_username)}</div>
         <div class="reply-quote-text">${escapeHTML((msg.reply_to_text || '').slice(0, 80))}</div>
       </div>`
    : '';

  const deleteBtn = (isMine || isAdmin) ? `
    <button class="msg-action-btn danger" title="Delete" data-action="delete">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
    </button>` : '';

  const pinBtn = isAdmin ? `
    <button class="msg-action-btn pin" title="Pin message" data-action="pin">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>
    </button>` : '';

  wrapper.innerHTML =
    avatarHtml +
    '<div class="msg-content">' +
    senderHtml +
    '<div style="position:relative">' +
    '<div class="msg-actions">' +
    '<button class="msg-action-btn" title="👍" data-action="react" data-emoji="👍">👍</button>' +
    '<button class="msg-action-btn" title="❤️" data-action="react" data-emoji="❤️">❤️</button>' +
    '<button class="msg-action-btn" title="🔥" data-action="react" data-emoji="🔥">🔥</button>' +
    '<button class="msg-action-btn" title="Reply" data-action="reply"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 17H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v5"/><polyline points="9 11 12 14 22 9"/></svg></button>' +
    pinBtn +
    deleteBtn +
    '</div>' +
    '<div class="msg-bubble">' + replyHtml + '<div class="msg-text">' + renderMessageText(msg.text) + '</div><div class="msg-meta">' + time + '</div></div>' +
    '</div>' +
    '<div class="msg-reactions" id="rxns-' + msgId + '"></div>' +
    '</div>';

  // Wire toolbar actions
  wrapper.querySelectorAll('[data-action]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const action = btn.dataset.action;
      if (action === 'react')   addReaction(msgId, btn.dataset.emoji);
      if (action === 'reply')   openReplyBar(msg.username, msg.text, msg.id);
      if (action === 'delete')  deleteMessage(msgId);
      if (action === 'pin')     pinMessage(msgId);
    });
  });

  // Reply quote click → jump to original
  wrapper.querySelectorAll('.msg-reply-quote').forEach(el => {
    el.addEventListener('click', () => jumpToMsg(parseInt(el.dataset.jump)));
  });

  // Avatar / sender → profile
  wrapper.querySelectorAll('[data-user]').forEach(el => {
    el.addEventListener('click', () => showProfile(msg.username, msg.avatar_color, msg.role || msg.user_role, msg.bio));
  });

  msgsList.appendChild(wrapper);
}

function appendDeletedMessage(msg) {
  const grouped = (lastMsgUser === msg.username);
  lastMsgUser = msg.username;
  const wrapper = document.createElement('div');
  wrapper.className = 'msg' + (currentUser && msg.username === currentUser.username ? ' mine' : '') + (grouped ? ' grouped' : '') + ' no-anim';
  wrapper.dataset.msgId = msg.id;
  const color = msg.avatar_color || '#4f59e8';
  const avatarHtml = grouped
    ? '<div class="msg-avatar-gap"></div>'
    : `<div class="msg-avatar" style="background:${escapeHTML(color)}">${escapeHTML(msg.username[0].toUpperCase())}</div>`;
  const isMine = currentUser && msg.username === currentUser.username;
  wrapper.innerHTML =
    avatarHtml +
    '<div class="msg-content"><div style="position:relative"><div class="msg-bubble" style="background:rgba(248,113,113,.04);border-color:rgba(248,113,113,.08)">' +
    '<em class="msg-deleted">This message was deleted</em>' +
    '<div class="msg-meta">' + formatTime(msg.created_at) + '</div></div></div></div>';
  msgsList.appendChild(wrapper);
}

function appendSystemMessage(text) {
  const div = document.createElement('div');
  div.className = 'system-msg';
  div.innerHTML = `<div class="system-msg-line"></div><div class="system-msg-text">${escapeHTML(text)}</div><div class="system-msg-line"></div>`;
  msgsList.appendChild(div);
  if (isAtBottom) scrollToBottom();
}

// ─── Reaction Rendering ──────────────────────────────────────────────────────
function renderReactions(wrapper, msgId, reactions) {
  const container = wrapper.querySelector('.msg-reactions') || document.getElementById('rxns-' + msgId);
  if (!container) return;
  container.innerHTML = '';
  if (!reactions || !reactions.length) return;
  reactions.forEach(r => {
    const users  = (r.users || '').split(',').filter(Boolean);
    const isMine = users.includes(currentUser?.username);
    const chip   = document.createElement('div');
    chip.className = 'rxn-chip' + (isMine ? ' mine' : '');

    // Inline short names: show up to 2 names, then "+N more"
    let namesLabel = '';
    if (users.length === 1) {
      namesLabel = users[0];
    } else if (users.length === 2) {
      namesLabel = users.join(', ');
    } else {
      namesLabel = `${users[0]} +${users.length - 1}`;
    }

    // Full list for the hover tooltip
    const fullNames = users.length > 5
      ? users.slice(0, 5).join(', ') + ` +${users.length - 5} more`
      : users.join(', ');

    chip.innerHTML =
      `<span>${r.emoji}</span>` +
      `<span class="rxn-count">${r.count}</span>` +
      `<span class="rxn-names">${escapeHTML(namesLabel)}</span>` +
      `<div class="rxn-tooltip">${escapeHTML(fullNames)}</div>`;

    chip.addEventListener('click', () => addReaction(msgId, r.emoji));
    container.appendChild(chip);
  });
}

// ─── Online Users ────────────────────────────────────────────────────────────
function renderOnlineUsers() {
  const unique = dedupeByUserId(onlineUsers);
  const isAdmin = currentUser?.role === 'admin';
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

  // Members panel
  const membersList  = $('membersList');
  const membersCount = $('membersPanelCount');
  if (!membersList) return;
  if (membersCount) membersCount.textContent = unique.length;
  membersList.innerHTML = '<div class="members-section-label">Online — ' + unique.length + '</div>';
  unique.forEach(u => {
    const isSelf = u.userId === currentUser?.id;
    const item   = document.createElement('div');
    item.className = 'member-item';

    let adminActions = '';
    if (isAdmin && !isSelf) {
      adminActions = `
        <div class="member-admin-actions">
          <button class="member-action-btn mute" data-uid="${u.userId}" data-uname="${escapeHTML(u.username)}" title="Mute user">🔇</button>
          <button class="member-action-btn kick" data-uid="${u.userId}" data-uname="${escapeHTML(u.username)}" title="Kick user">Kick</button>
        </div>`;
    }

    item.innerHTML =
      '<div class="member-avatar" style="background:' + escapeHTML(u.avatar_color || '#4f59e8') + '">' +
      u.username[0].toUpperCase() +
      '<span class="member-status-dot"></span></div>' +
      '<span class="member-name">' + escapeHTML(u.username) + '</span>' +
      adminActions;

    item.querySelector('.member-avatar, .member-name')?.addEventListener('click', () =>
      showProfile(u.username, u.avatar_color, u.role, u.bio));

    if (isAdmin && !isSelf) {
      item.querySelector('.member-action-btn.kick')?.addEventListener('click', (e) => {
        e.stopPropagation();
        kickUser(parseInt(e.currentTarget.dataset.uid), e.currentTarget.dataset.uname);
      });
      item.querySelector('.member-action-btn.mute')?.addEventListener('click', (e) => {
        e.stopPropagation();
        showMuteMenu(parseInt(e.currentTarget.dataset.uid), e.currentTarget.dataset.uname, e.currentTarget);
      });
    }

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
  if (isMuted) { showToast('You are muted by an admin.', 'error'); return; }

  // BUG FIX #3: Include reply context in emit
  const payload = { roomId: currentRoom.id, text };
  if (replyContext) {
    payload.replyToId       = replyContext.id;
    payload.replyToUsername = replyContext.username;
    payload.replyToText     = replyContext.text;
  }

  socket.emit('chat_message', payload);
  msgInput.value = '';
  charCount.textContent = '';
  charCount.className   = 'char-count';
  if (isTyping) { isTyping = false; socket.emit('typing_stop', currentRoom.id); }
  clearTimeout(typingTimer);
  isAtBottom = true;
  closeReplyBar();
  scrollToBottom();
}

sendBtn.addEventListener('click', sendMessage);
msgInput.addEventListener('keydown', (e) => {
  // ── @mention dropdown keyboard nav ──────────────────────────────────────────
  if (mentionActive) {
    const dd    = $('mentionDropdown');
    const items = dd ? [...dd.querySelectorAll('.mention-item')] : [];
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      mentionSelected = Math.min(mentionSelected + 1, items.length - 1);
      items.forEach((el, i) => el.classList.toggle('selected', i === mentionSelected));
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      mentionSelected = Math.max(mentionSelected - 1, 0);
      items.forEach((el, i) => el.classList.toggle('selected', i === mentionSelected));
      return;
    }
    if (e.key === 'Tab' || (e.key === 'Enter' && mentionSelected >= 0 && items.length)) {
      const sel = items[mentionSelected] || items[0];
      if (sel) { e.preventDefault(); completeMention(sel.dataset.username); return; }
    }
    if (e.key === 'Escape') {
      e.preventDefault();
      hideMentionDropdown();
      return;
    }
  }
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});

// ─── Typing Emit ─────────────────────────────────────────────────────────────
msgInput.addEventListener('input', () => {
  if (!currentRoom) return;
  const len = msgInput.value.length;
  if (len > 1500) {
    charCount.textContent = `${len} / 2000`;
    charCount.className   = len > 1900 ? 'char-count limit' : 'char-count warn';
  } else {
    charCount.textContent = '';
    charCount.className   = 'char-count';
  }
  if (!isTyping) { isTyping = true; socket.emit('typing_start', currentRoom.id); }
  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => { isTyping = false; socket.emit('typing_stop', currentRoom.id); }, 1500);
  // @mention detection
  checkMention();
});

// ─── @Mention System ──────────────────────────────────────────────────────────
function checkMention() {
  const val    = msgInput.value;
  const cursor = msgInput.selectionStart;
  const before = val.slice(0, cursor);
  const match  = before.match(/@(\w*)$/);
  if (match) {
    mentionStart  = cursor - match[0].length;
    mentionActive = true;
    renderMentionDropdown(match[1].toLowerCase());
  } else {
    hideMentionDropdown();
  }
}

function renderMentionDropdown(query) {
  const dd = $('mentionDropdown');
  if (!dd) return;

  const all     = dedupeByUserId(onlineUsers);
  const matches = all
    .filter(u => u.userId !== currentUser?.id)
    .filter(u => !query || u.username.toLowerCase().startsWith(query))
    .slice(0, 7);

  if (!matches.length) { hideMentionDropdown(); return; }

  mentionSelected = 0;
  dd.innerHTML    = '';

  matches.forEach((u, i) => {
    const item = document.createElement('div');
    item.className      = 'mention-item' + (i === 0 ? ' selected' : '');
    item.dataset.username = u.username;
    const roleTag = u.role === 'admin'
      ? '<span class="mention-role">Admin</span>'
      : '';
    item.innerHTML =
      `<div class="mention-avatar" style="background:${escapeHTML(u.avatar_color || '#4f59e8')}">${u.username[0].toUpperCase()}</div>` +
      `<span class="mention-name">${escapeHTML(u.username)}</span>` +
      roleTag;
    item.addEventListener('mouseenter', () => {
      mentionSelected = i;
      dd.querySelectorAll('.mention-item').forEach((el, j) => el.classList.toggle('selected', j === i));
    });
    item.addEventListener('click', () => completeMention(u.username));
    dd.appendChild(item);
  });

  dd.style.display = 'flex';
}

function completeMention(username) {
  const val    = msgInput.value;
  const cursor = msgInput.selectionStart;
  const before = val.slice(0, mentionStart);
  const after  = val.slice(cursor);
  msgInput.value = before + '@' + username + ' ' + after;
  const newPos   = before.length + username.length + 2;
  msgInput.setSelectionRange(newPos, newPos);
  hideMentionDropdown();
  msgInput.focus();
}

function hideMentionDropdown() {
  mentionActive   = false;
  mentionStart    = -1;
  mentionSelected = -1;
  const dd = $('mentionDropdown');
  if (dd) dd.style.display = 'none';
}

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

// ─── Sidebar Toggle (mobile) ──────────────────────────────────────────────────
function openSidebar() {
  $('sidebar').classList.add('open');
  $('sidebarBackdrop').classList.add('show');
}
function closeSidebar() {
  $('sidebar').classList.remove('open');
  $('sidebarBackdrop').classList.remove('show');
}
function closeSidebarOnMobile() {
  if (window.innerWidth <= 680) closeSidebar();
}

$('sidebarToggle').addEventListener('click', (e) => {
  e.stopPropagation(); // CRITICAL: prevent bubbling to main which would re-close immediately
  if ($('sidebar').classList.contains('open')) closeSidebar();
  else openSidebar();
});
$('sidebarCloseBtn').addEventListener('click', (e) => {
  e.stopPropagation();
  closeSidebar();
});
$('sidebarBackdrop').addEventListener('click', closeSidebar);

// Close sidebar when tapping the main content area (not the toggle)
$('main').addEventListener('click', () => {
  if (window.innerWidth <= 680) closeSidebar();
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
      // Close picker after inserting emoji
      picker.classList.remove('open');
      $('emojiBtn').classList.remove('active');
    });
    grid.appendChild(btn);
  });

  $('emojiBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    picker.classList.toggle('open');
    $('emojiBtn').classList.toggle('active', picker.classList.contains('open'));
  });

  // BUG FIX #7: Close emoji picker on outside click
  document.addEventListener('click', (e) => {
    if (!picker.contains(e.target) && e.target !== $('emojiBtn')) {
      picker.classList.remove('open');
      $('emojiBtn').classList.remove('active');
    }
    // Also close mention dropdown when clicking outside the input area
    const dd = $('mentionDropdown');
    if (dd && !dd.contains(e.target) && e.target !== msgInput) {
      hideMentionDropdown();
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  SEARCH — XSS VULNERABLE (intentional for ShieldWatch demo)
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
// FILE BROWSER
// ─────────────────────────────────────────────────────────────────────────────
const FILE_ICONS = {
  js:'🟨', ts:'🟦', json:'📋', html:'🌐', css:'🎨',
  md:'📝', txt:'📄', sql:'🗄️', env:'🔐', py:'🐍',
  sh:'⚙️', log:'📜', xml:'📰', yml:'⚙️', yaml:'⚙️',
};
function getFileIcon(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  return FILE_ICONS[ext] || '📄';
}

$('filesBtn').addEventListener('click', openFilesModal);
$('filesClose').addEventListener('click', closeFilesModal);
$('filesModal').addEventListener('click', (e) => { if (e.target === $('filesModal')) closeFilesModal(); });

function openFilesModal()  { $('filesModal').classList.add('open'); loadFiles(); }
function closeFilesModal() { $('filesModal').classList.remove('open'); }

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
// ⚠️  FILE VIEWER — PATH TRAVERSAL entry point (intentional for ShieldWatch demo)
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
  $('viewerContent').textContent  = 'Select a file from the list to preview its contents.';
  $('viewerFileName').textContent = 'No file selected';
  $('viewerIcon').textContent     = '📄';
});

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
  const body    = $('profileBody');
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
    $('broadcastModal').classList.remove('open');
    $('slowModeModal').classList.remove('open');
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

// ─── Reply Bar ───────────────────────────────────────────────────────────────
function openReplyBar(username, text, id) {
  replyContext = { username, text, id };
  const bar = $('replyBar');
  if (!bar) return;
  $('replyBarWho').textContent    = username;
  $('replyBarPreview').textContent = ' · ' + text.slice(0, 60);
  bar.classList.add('visible');
  msgInput.focus();
}

function closeReplyBar() {
  replyContext = null;
  const bar = $('replyBar');
  if (bar) bar.classList.remove('visible');
}

const replyBarCloseBtn = $('replyBarClose');
if (replyBarCloseBtn) replyBarCloseBtn.addEventListener('click', closeReplyBar);

// ─── Bug Fix #1: Delete broadcasts to all users ───────────────────────────────
function deleteMessage(msgId) {
  if (!currentRoom) return;
  socket.emit('delete_message', { msgId, roomId: currentRoom.id });
}

// ─── Bug Fix #2: Reactions broadcast to all users ────────────────────────────
function addReaction(msgId, emoji) {
  if (!currentRoom || !msgId) return;
  socket.emit('add_reaction', { msgId, roomId: currentRoom.id, emoji });
}

// ─── Pinned Message Bar ───────────────────────────────────────────────────────
function showPinnedBar({ msgId, text, username, pinnedBy }) {
  $('pinnedBarUser').textContent = username;
  $('pinnedBarText').textContent = text.slice(0, 80);
  $('pinnedBar').style.display = 'flex';

  $('pinnedBarJump').onclick = () => jumpToMsg(msgId);

  const unpinBtn = $('pinnedBarUnpin');
  if (unpinBtn && currentUser?.role === 'admin') {
    unpinBtn.style.display = 'flex';
    unpinBtn.onclick = () => {
      socket.emit('unpin_message', { roomId: currentRoom.id });
    };
  }
}

function hidePinnedBar() {
  $('pinnedBar').style.display = 'none';
}

// ─── Slow Mode UI ─────────────────────────────────────────────────────────────
function updateSlowModeUI() {
  const bar = $('slowModeBar');
  if (!bar) return;
  if (slowModeActive > 0) {
    $('slowModeText').textContent = `Slow mode — 1 message every ${slowModeActive}s`;
    bar.style.display = 'flex';
  } else {
    bar.style.display = 'none';
    $('slowCountdown').textContent = '';
    if (slowCdTimer) clearInterval(slowCdTimer);
  }
}

function startSlowCountdown(seconds) {
  let remaining = Math.ceil(seconds);
  $('slowCountdown').textContent = `${remaining}s`;
  msgInput.disabled = true;
  if (slowCdTimer) clearInterval(slowCdTimer);
  slowCdTimer = setInterval(() => {
    remaining--;
    if (remaining <= 0) {
      clearInterval(slowCdTimer);
      $('slowCountdown').textContent = '';
      if (!isMuted) msgInput.disabled = false;
    } else {
      $('slowCountdown').textContent = `${remaining}s`;
    }
  }, 1000);
}

// ─── Announcement Banner ──────────────────────────────────────────────────────
function showAnnouncementBanner(text, by) {
  const banner = $('announceBanner');
  $('announceBy').textContent   = `📢 ${by}:`;
  $('announceText').textContent = text;
  banner.style.display = 'block';
  // Auto-dismiss after 12s
  setTimeout(() => { if (banner.style.display !== 'none') hideBanner(); }, 12000);
}

function hideBanner() {
  const b = $('announceBanner');
  b.style.opacity = '0';
  b.style.transition = 'opacity .3s';
  setTimeout(() => { b.style.display = 'none'; b.style.opacity = ''; }, 300);
}

$('announceDismiss').addEventListener('click', hideBanner);

// ─── Toast Notifications ──────────────────────────────────────────────────────
function showToast(message, type = 'info', duration = 4000) {
  const container = $('toastContainer');
  const toast     = document.createElement('div');
  const icons     = { success: '✓', error: '✕', info: 'ℹ' };
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span class="toast-icon">${icons[type] || 'ℹ'}</span><span>${escapeHTML(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => toast.remove(), 250);
  }, duration);
}

// ─── Admin Actions ────────────────────────────────────────────────────────────
function kickUser(targetUserId, targetUsername) {
  if (!confirm(`Remove ${targetUsername} from the chat?`)) return;
  socket.emit('kick_user', {
    targetUserId, targetUsername, roomId: currentRoom?.id,
  });
}

function showMuteMenu(targetUserId, targetUsername, anchorEl) {
  // Remove any existing mute menu
  document.querySelectorAll('.mute-menu').forEach(m => m.remove());

  const menu = document.createElement('div');
  menu.className = 'mute-menu';
  menu.style.cssText = `
    position:fixed;z-index:300;background:var(--s3);border:1px solid var(--b1);
    border-radius:10px;padding:6px;box-shadow:0 8px 24px rgba(0,0,0,.5);
    display:flex;flex-direction:column;gap:2px;min-width:160px;
  `;

  const options = [
    { label: '🔇 Mute 5 min',    ms: 5  * 60 * 1000 },
    { label: '🔇 Mute 30 min',   ms: 30 * 60 * 1000 },
    { label: '🔇 Mute 1 hour',   ms: 60 * 60 * 1000 },
    { label: '🔇 Permanent',     ms: -1 },
    { label: '🔊 Unmute',        ms: 0  },
  ];

  options.forEach(opt => {
    const btn = document.createElement('button');
    btn.textContent = opt.label;
    btn.style.cssText = `
      background:none;border:none;color:var(--t2);text-align:left;
      padding:7px 12px;border-radius:7px;font-size:13px;font-weight:500;cursor:pointer;
      transition:background .1s,color .1s;
    `;
    btn.addEventListener('mouseover', () => { btn.style.background='rgba(255,255,255,.05)'; btn.style.color='var(--t1)'; });
    btn.addEventListener('mouseout',  () => { btn.style.background='none'; btn.style.color='var(--t2)'; });
    btn.addEventListener('click', () => {
      if (opt.ms === 0) {
        socket.emit('unmute_user', { targetUserId, targetUsername });
      } else {
        socket.emit('mute_user', { targetUserId, targetUsername, durationMs: opt.ms });
      }
      menu.remove();
    });
    menu.appendChild(btn);
  });

  const rect = anchorEl.getBoundingClientRect();
  menu.style.top  = `${rect.bottom + 4}px`;
  menu.style.left = `${rect.left}px`;
  document.body.appendChild(menu);

  const closeMenu = (e) => {
    if (!menu.contains(e.target)) { menu.remove(); document.removeEventListener('click', closeMenu); }
  };
  setTimeout(() => document.addEventListener('click', closeMenu), 0);
}

function pinMessage(msgId) {
  if (!currentRoom) return;
  socket.emit('pin_message', { msgId, roomId: currentRoom.id });
  showToast('Message pinned.', 'success');
}

// ─── Admin UI Init ────────────────────────────────────────────────────────────
function initAdminUI() {
  if (currentUser?.role !== 'admin') return;

  // Broadcast modal
  $('broadcastBtn').addEventListener('click', () => {
    $('broadcastModal').classList.add('open');
    $('broadcastText').focus();
  });
  $('broadcastClose').addEventListener('click', () => $('broadcastModal').classList.remove('open'));
  $('broadcastModal').addEventListener('click', (e) => {
    if (e.target === $('broadcastModal')) $('broadcastModal').classList.remove('open');
  });
  $('broadcastSend').addEventListener('click', () => {
    const text = $('broadcastText').value.trim();
    if (!text) return;
    socket.emit('broadcast_announcement', { text });
    $('broadcastText').value = '';
    $('broadcastModal').classList.remove('open');
    showToast('Announcement sent to all rooms.', 'success');
  });
  $('broadcastText').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      $('broadcastSend').click();
    }
  });

  // Slow mode modal
  $('slowModeBtn').addEventListener('click', () => {
    $('slowModeModal').classList.add('open');
    updateSlowModePresetBtns();
  });
  $('slowModeClose').addEventListener('click', () => $('slowModeModal').classList.remove('open'));
  $('slowModeModal').addEventListener('click', (e) => {
    if (e.target === $('slowModeModal')) $('slowModeModal').classList.remove('open');
  });

  document.querySelectorAll('.slow-preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const sec = parseInt(btn.dataset.sec, 10);
      applySlowMode(sec);
    });
  });

  $('slowModeCustomApply').addEventListener('click', () => {
    const val = parseInt($('slowModeCustom').value, 10);
    if (!isNaN(val) && val > 0) applySlowMode(val);
  });
}

function applySlowMode(seconds) {
  if (!currentRoom) return;
  socket.emit('set_slow_mode', { roomId: currentRoom.id, seconds });
  $('slowModeModal').classList.remove('open');
  updateSlowModePresetBtns(seconds);
}

function updateSlowModePresetBtns(active) {
  const current = active !== undefined ? active : slowModeActive;
  document.querySelectorAll('.slow-preset-btn').forEach(btn => {
    btn.classList.toggle('active', parseInt(btn.dataset.sec, 10) === current);
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escapeHTML(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Render message text — escapes HTML then highlights @mentions
function renderMessageText(text) {
  const escaped = escapeHTML(text);
  return escaped.replace(/@(\w+)/g, (match, name) => {
    const isMe = name === currentUser?.username;
    return `<span class="mention-highlight${isMe ? ' me' : ''}">@${name}</span>`;
  });
}

function formatTime(isoString) {
  if (!isoString) return '';
  return new Date(isoString).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatDateLabel(isoString) {
  if (!isoString) return 'Today';
  const d         = new Date(isoString);
  const today     = new Date();
  const yesterday = new Date(today); yesterday.setDate(today.getDate() - 1);
  if (d.toDateString() === today.toDateString())     return 'Today';
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' });
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
init();
