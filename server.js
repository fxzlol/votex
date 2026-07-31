const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname))); // отдаём index.html и статику

const JWT_SECRET = 'votex-secret-key';
const SALT_ROUNDS = 10;

// Хранилища в памяти
const users = new Map();         // id -> user
const tokens = new Map();       // token -> userId
const friendships = new Map();  // userId -> Set<friendId>
const friendRequests = new Map(); // отправитель -> { to: userId, status: 'pending' }
const servers = new Map();      // id -> server
const categories = new Map();   // serverId -> [category]
const channels = new Map();     // id -> channel
const messages = new Map();     // channelId/room -> [message]
const groups = new Map();       // id -> group
const groupMembers = new Map(); // groupId -> Set<memberId>
const groupMessages = new Map();// groupId -> [message]
const blocked = new Map();      // userId -> Set<blockedId>

// Авто-создание дефолтного пользователя для тестов
(async () => {
  const adminPass = await bcrypt.hash('admin', SALT_ROUNDS);
  users.set(1, {
    id: 1, username: 'admin', display_name: 'Admin',
    password: adminPass, avatar_url: '', avatar_color: '#5865f2',
    about: 'Hello!'
  });
})();

// Middleware проверки JWT
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Вспомогательные функции
function getUserSafe(user) {
  const { password, ...safe } = user;
  return safe;
}

function generateToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '7d' });
}

// ================= REST API =================

// Регистрация
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const exists = [...users.values()].find(u => u.username === username);
  if (exists) return res.status(400).json({ error: 'Username taken' });
  const id = uuidv4().slice(0, 8);
  const hashed = await bcrypt.hash(password, SALT_ROUNDS);
  const user = { id, username, display_name: username, password: hashed, avatar_url: '', avatar_color: '#5865f2', about: '' };
  users.set(id, user);
  const token = generateToken(id);
  tokens.set(token, id);
  res.json({ token, user: getUserSafe(user) });
});

// Логин
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = [...users.values()].find(u => u.username === username);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid credentials' });
  const token = generateToken(user.id);
  tokens.set(token, user.id);
  res.json({ token, user: getUserSafe(user) });
});

// Текущий пользователь
app.get('/api/users/me', authMiddleware, (req, res) => {
  const user = users.get(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(getUserSafe(user));
});

// Обновление профиля
app.put('/api/users/me', authMiddleware, (req, res) => {
  const user = users.get(req.userId);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { username, display_name, about, avatar_color, avatar_url } = req.body;
  if (username) user.username = username;
  if (display_name) user.display_name = display_name;
  if (about !== undefined) user.about = about;
  if (avatar_color) user.avatar_color = avatar_color;
  if (avatar_url !== undefined) user.avatar_url = avatar_url;
  users.set(req.userId, user);
  res.json(getUserSafe(user));
});

// Смена пароля
app.put('/api/users/me/password', authMiddleware, async (req, res) => {
  const user = users.get(req.userId);
  const { oldPassword, newPassword } = req.body;
  const valid = await bcrypt.compare(oldPassword, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid old password' });
  user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
  users.set(req.userId, user);
  res.json({ success: true });
});

// Удаление аккаунта
app.delete('/api/users/me', authMiddleware, (req, res) => {
  users.delete(req.userId);
  res.json({ success: true });
});

// Поиск пользователей
app.get('/api/users/search', authMiddleware, (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  const results = [...users.values()]
    .filter(u => u.id !== req.userId && u.username.toLowerCase().includes(q))
    .map(getUserSafe);
  res.json(results);
});

// Профиль другого пользователя
app.get('/api/users/:id', authMiddleware, (req, res) => {
  const user = users.get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(getUserSafe(user));
});

// ---------- Друзья ----------
app.get('/api/friends', authMiddleware, (req, res) => {
  const myFriends = friendships.get(req.userId) || new Set();
  const pend = friendRequests.get(req.userId) || [];
  const list = [...myFriends].map(id => {
    const u = users.get(id);
    return { id, username: u.username, avatar_url: u.avatar_url, avatar_color: u.avatar_color, status: 'accepted' };
  });
  const pending = pend.map(req => ({
    id: req.from,
    username: users.get(req.from)?.username || 'unknown',
    avatar_url: users.get(req.from)?.avatar_url,
    avatar_color: users.get(req.from)?.avatar_color,
    status: 'pending',
    sender: 'them'
  }));
  res.json([...list, ...pending]);
});

app.post('/api/friends/request', authMiddleware, (req, res) => {
  const friendId = req.body.friendId;
  if (!users.has(friendId)) return res.status(404).json({ error: 'User not found' });
  // добавляем запрос получателю
  const reqs = friendRequests.get(friendId) || [];
  if (!reqs.find(r => r.from === req.userId)) {
    reqs.push({ from: req.userId, status: 'pending' });
    friendRequests.set(friendId, reqs);
  }
  res.json({ success: true });
});

app.post('/api/friends/accept', authMiddleware, (req, res) => {
  const friendId = req.body.friendId;
  // удаляем запрос
  const reqs = friendRequests.get(req.userId) || [];
  friendRequests.set(req.userId, reqs.filter(r => r.from !== friendId));
  // добавляем в друзья обоим
  if (!friendships.has(req.userId)) friendships.set(req.userId, new Set());
  friendships.get(req.userId).add(friendId);
  if (!friendships.has(friendId)) friendships.set(friendId, new Set());
  friendships.get(friendId).add(req.userId);
  res.json({ success: true });
});

app.post('/api/friends/remove', authMiddleware, (req, res) => {
  const friendId = req.body.friendId;
  friendships.get(req.userId)?.delete(friendId);
  friendships.get(friendId)?.delete(req.userId);
  res.json({ success: true });
});

app.post('/api/friends/block', authMiddleware, (req, res) => {
  const blockId = req.body.friendId;
  if (!blocked.has(req.userId)) blocked.set(req.userId, new Set());
  blocked.get(req.userId).add(blockId);
  res.json({ success: true });
});

// ---------- Серверы ----------
app.get('/api/servers', authMiddleware, (req, res) => {
  const userServers = [...servers.values()].filter(s => s.members.has(req.userId));
  const safe = userServers.map(s => ({
    id: s.id, name: s.name, description: s.description,
    avatar_url: s.avatar_url, invite_code: s.invite_code,
    owner_id: s.owner_id
  }));
  res.json(safe);
});

app.post('/api/servers', authMiddleware, (req, res) => {
  const { name, description } = req.body;
  const id = uuidv4().slice(0, 8);
  const invite_code = uuidv4().slice(0, 6);
  const server = {
    id, name, description: description || '',
    owner_id: req.userId, invite_code, avatar_url: '',
    members: new Set([req.userId])
  };
  servers.set(id, server);
  categories.set(id, []);
  res.json({ id, name, invite_code });
});

app.get('/api/servers/:id/categories', authMiddleware, (req, res) => {
  const serverId = req.params.id;
  const cats = categories.get(serverId) || [];
  // добавим каналы в категории
  const result = cats.map(cat => ({
    id: cat.id, name: cat.name,
    channels: (cat.channelIds || []).map(chId => {
      const ch = channels.get(chId);
      return ch ? { id: ch.id, name: ch.name, type: ch.type, slowmode: ch.slowmode, is_private: ch.is_private } : null;
    }).filter(Boolean)
  }));
  res.json(result);
});

app.post('/api/servers/:id/categories', authMiddleware, (req, res) => {
  const serverId = req.params.id;
  const { name } = req.body;
  const catId = uuidv4().slice(0, 8);
  const cat = { id: catId, name, channelIds: [] };
  const cats = categories.get(serverId) || [];
  cats.push(cat);
  categories.set(serverId, cats);
  res.json(cat);
});

app.post('/api/servers/:id/channels', authMiddleware, (req, res) => {
  const serverId = req.params.id;
  const { name, type, category_id } = req.body;
  const chId = uuidv4().slice(0, 8);
  const channel = {
    id: chId, name, type: type || 'text',
    server_id: serverId, category_id: category_id || null,
    slowmode: 0, is_private: false
  };
  channels.set(chId, channel);
  // добавить в категорию
  if (category_id) {
    const cats = categories.get(serverId) || [];
    const cat = cats.find(c => c.id === category_id);
    if (cat) cat.channelIds.push(chId);
    categories.set(serverId, cats);
  } else {
    // категория "без категории"? добавим в общую
    const cats = categories.get(serverId) || [];
    if (!cats.find(c => c.id === 'general')) {
      cats.unshift({ id: 'general', name: 'General', channelIds: [chId] });
    } else {
      cats.find(c => c.id === 'general').channelIds.push(chId);
    }
    categories.set(serverId, cats);
  }
  res.json(channel);
});

app.put('/api/servers/:id', authMiddleware, (req, res) => {
  const server = servers.get(req.params.id);
  if (!server || server.owner_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  const { name, description, avatar_url } = req.body;
  if (name) server.name = name;
  if (description !== undefined) server.description = description;
  if (avatar_url !== undefined) server.avatar_url = avatar_url;
  res.json({ success: true });
});

app.delete('/api/servers/:id', authMiddleware, (req, res) => {
  const server = servers.get(req.params.id);
  if (!server || server.owner_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  servers.delete(req.params.id);
  res.json({ success: true });
});

app.post('/api/servers/join', authMiddleware, (req, res) => {
  const { inviteCode } = req.body;
  const server = [...servers.values()].find(s => s.invite_code === inviteCode);
  if (!server) return res.status(404).json({ error: 'Invalid invite' });
  server.members.add(req.userId);
  res.json({ success: true });
});

app.get('/api/servers/:id/members', authMiddleware, (req, res) => {
  const server = servers.get(req.params.id);
  if (!server) return res.status(404).json({ error: 'Not found' });
  const members = [...server.members].map(id => {
    const u = users.get(id);
    return {
      id: u.id, username: u.username, avatar_url: u.avatar_url,
      avatar_color: u.avatar_color,
      role: server.owner_id === id ? 'owner' : 'member'
    };
  });
  res.json(members);
});

app.post('/api/servers/:id/kick/:userId', authMiddleware, (req, res) => {
  const server = servers.get(req.params.id);
  if (!server || server.owner_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  server.members.delete(req.params.userId);
  res.json({ success: true });
});

app.post('/api/servers/:id/ban/:userId', authMiddleware, (req, res) => {
  // упрощённо: просто кик
  const server = servers.get(req.params.id);
  if (!server || server.owner_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  server.members.delete(req.params.userId);
  res.json({ success: true });
});

app.put('/api/servers/:id/members/:userId/role', authMiddleware, (req, res) => {
  // для простоты не реализуем роли, кроме owner
  res.json({ success: true });
});

app.post('/api/servers/:id/invite/regenerate', authMiddleware, (req, res) => {
  const server = servers.get(req.params.id);
  if (!server || server.owner_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  server.invite_code = uuidv4().slice(0, 6);
  res.json({ invite_code: server.invite_code });
});

// ---------- Каналы ----------
app.get('/api/channels/:id/messages', authMiddleware, (req, res) => {
  const chId = req.params.id;
  const msgs = messages.get(chId) || [];
  const enriched = msgs.map(m => {
    const u = users.get(m.user_id);
    return {
      ...m,
      username: u?.username,
      avatar_url: u?.avatar_url,
      avatar_color: u?.avatar_color
    };
  });
  res.json(enriched);
});

app.delete('/api/channels/:id', authMiddleware, (req, res) => {
  channels.delete(req.params.id);
  res.json({ success: true });
});

app.put('/api/channels/:id', authMiddleware, (req, res) => {
  const ch = channels.get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Not found' });
  const { name, slowmode, is_private } = req.body;
  if (name) ch.name = name;
  if (slowmode !== undefined) ch.slowmode = slowmode;
  if (is_private !== undefined) ch.is_private = is_private;
  channels.set(req.params.id, ch);
  res.json({ success: true });
});

// Права каналов (заглушка)
app.get('/api/channels/:id/permissions', authMiddleware, (req, res) => {
  res.json([]);
});
app.post('/api/channels/:id/permissions', authMiddleware, (req, res) => {
  res.json({ success: true });
});
app.delete('/api/channels/:id/permissions/:userId', authMiddleware, (req, res) => {
  res.json({ success: true });
});

// ---------- Личные сообщения ----------
app.get('/api/dm/:friendId', authMiddleware, (req, res) => {
  const room = [req.userId, req.params.friendId].sort().join('-');
  const msgs = messages.get(room) || [];
  const enriched = msgs.map(m => {
    const u = users.get(m.sender_id);
    return { ...m, username: u?.username, avatar_url: u?.avatar_url, avatar_color: u?.avatar_color };
  });
  res.json(enriched);
});

// Удаление DM
app.delete('/api/messages/dm/:id', authMiddleware, (req, res) => {
  // поиск и удаление (упрощённо)
  for (const [room, msgs] of messages.entries()) {
    const idx = msgs.findIndex(m => m.id === req.params.id);
    if (idx !== -1) {
      msgs.splice(idx, 1);
      break;
    }
  }
  res.json({ success: true });
});

// Удаление сообщения канала
app.delete('/api/messages/:id', authMiddleware, (req, res) => {
  for (const [chId, msgs] of messages.entries()) {
    const idx = msgs.findIndex(m => m.id === req.params.id);
    if (idx !== -1) {
      msgs.splice(idx, 1);
      break;
    }
  }
  res.json({ success: true });
});

// Редактирование сообщения
app.put('/api/messages/:id', authMiddleware, (req, res) => {
  const { content } = req.body;
  for (const [key, msgs] of messages.entries()) {
    const msg = msgs.find(m => m.id === req.params.id);
    if (msg) {
      msg.content = content;
      break;
    }
  }
  res.json({ success: true });
});

// Пин (заглушка)
app.post('/api/messages/:id/pin', authMiddleware, (req, res) => {
  res.json({ success: true });
});

// ---------- Группы ----------
app.get('/api/groups', authMiddleware, (req, res) => {
  const userGroups = [...groups.values()].filter(g => g.members.has(req.userId));
  res.json(userGroups.map(g => ({
    id: g.id, name: g.name, avatar_color: g.avatar_color, owner_id: g.owner_id
  })));
});

app.post('/api/groups', authMiddleware, (req, res) => {
  const { name, memberIds } = req.body;
  const id = uuidv4().slice(0, 8);
  const group = {
    id, name, owner_id: req.userId,
    avatar_color: '#5865f2',
    members: new Set([req.userId, ...(memberIds || [])])
  };
  groups.set(id, group);
  res.json({ id, name });
});

app.get('/api/groups/:id/messages', authMiddleware, (req, res) => {
  const msgs = groupMessages.get(req.params.id) || [];
  const enriched = msgs.map(m => {
    const u = users.get(m.sender_id);
    return { ...m, username: u?.username, avatar_url: u?.avatar_url, avatar_color: u?.avatar_color };
  });
  res.json(enriched);
});

app.get('/api/groups/:id/members', authMiddleware, (req, res) => {
  const group = groups.get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Not found' });
  const members = [...group.members].map(id => {
    const u = users.get(id);
    return { id: u.id, username: u.username, avatar_url: u.avatar_url, avatar_color: u.avatar_color };
  });
  res.json(members);
});

app.delete('/api/groups/:id/members/:userId', authMiddleware, (req, res) => {
  const group = groups.get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Not found' });
  group.members.delete(req.params.userId);
  res.json({ success: true });
});

app.delete('/api/groups/:id', authMiddleware, (req, res) => {
  groups.delete(req.params.id);
  res.json({ success: true });
});

app.get('/api/groups/:id/invite', authMiddleware, (req, res) => {
  res.json({ invite_code: 'group-' + req.params.id });
});

// ================= Socket.IO =================
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.userId = decoded.id;
    next();
  } catch (e) {
    next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  console.log(`User ${socket.userId} connected`);

  // Присоединение к DM комнате
  socket.on('dm-join', (friendId) => {
    const room = [socket.userId, friendId].sort().join('-');
    socket.join(room);
    socket.currentDmRoom = room;
  });

  socket.on('dm-leave', (room) => {
    if (room) socket.leave(room);
  });

  // Отправка DM
  socket.on('dm-message', (data) => {
    const { friendId, content, repliedTo } = data;
    const room = [socket.userId, friendId].sort().join('-');
    const msg = {
      id: uuidv4(),
      sender_id: socket.userId,
      content,
      timestamp: new Date().toISOString(),
      replied_to: repliedTo || null
    };
    if (!messages.has(room)) messages.set(room, []);
    messages.get(room).push(msg);
    const user = users.get(socket.userId);
    io.to(room).emit('dm-message', {
      ...msg,
      username: user.username,
      avatar_url: user.avatar_url,
      avatar_color: user.avatar_color
    });
  });

  // Каналы сервера
  socket.on('join-channel', (channelId) => {
    socket.join('channel-' + channelId);
    socket.currentChannelRoom = 'channel-' + channelId;
  });

  socket.on('leave-channel', (room) => {
    if (room) socket.leave(room);
  });

  socket.on('send-message', (data) => {
    const { channelId, content, repliedTo } = data;
    const ch = channels.get(channelId);
    if (!ch) return;
    const msg = {
      id: uuidv4(),
      user_id: socket.userId,
      content,
      timestamp: new Date().toISOString(),
      replied_to: repliedTo || null
    };
    if (!messages.has(channelId)) messages.set(channelId, []);
    messages.get(channelId).push(msg);
    const user = users.get(socket.userId);
    io.to('channel-' + channelId).emit('new-message', {
      ...msg,
      username: user.username,
      avatar_url: user.avatar_url,
      avatar_color: user.avatar_color
    });
  });

  // Группы
  socket.on('group-join', (groupId) => {
    socket.join('group-' + groupId);
  });

  socket.on('group-leave', (room) => {
    if (room) socket.leave(room);
  });

  socket.on('group-message', (data) => {
    const { groupId, content, repliedTo } = data;
    const msg = {
      id: uuidv4(),
      sender_id: socket.userId,
      content,
      timestamp: new Date().toISOString(),
      replied_to: repliedTo || null
    };
    if (!groupMessages.has(groupId)) groupMessages.set(groupId, []);
    groupMessages.get(groupId).push(msg);
    const user = users.get(socket.userId);
    io.to('group-' + groupId).emit('group-message', {
      ...msg,
      username: user.username,
      avatar_url: user.avatar_url,
      avatar_color: user.avatar_color
    });
  });

  // WebRTC сигнализация (прокси)
  socket.on('call-join', (room) => {
    socket.join(room);
    socket.to(room).emit('call-join', socket.userId);
  });
  socket.on('call-offer', ({ room, offer, to }) => {
    io.to(to).emit('call-offer', { from: socket.userId, offer });
  });
  socket.on('call-answer', ({ room, answer, to }) => {
    io.to(to).emit('call-answer', { from: socket.userId, answer });
  });
  socket.on('call-candidate', ({ room, candidate, to }) => {
    io.to(to).emit('call-candidate', { from: socket.userId, candidate });
  });
  socket.on('call-leave', (room) => {
    socket.to(room).emit('call-leave', socket.userId);
    socket.leave(room);
  });

  socket.on('disconnect', () => {
    console.log(`User ${socket.userId} disconnected`);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});