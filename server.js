const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = 'votex_secret_key_2025';
const users = [];
const servers = [];
const channels = [];
const categories = [];
const messages = [];
const dmMessages = [];
const groupMessages = [];
const groups = [];
const friends = [];
const blocked = [];
const sessions = [];

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    const token = header.split(' ')[1];
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = users.find(u => u.id === payload.id);
    if (!req.user) return res.status(401).json({ error: 'User not found' });
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function generateId() { return Math.floor(Math.random() * 1000000); }
function escapeHtml(text) { return text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// Auth API
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (users.find(u => u.username === username)) return res.status(400).json({ error: 'Username taken' });
  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: generateId(),
    username,
    password: hashed,
    display_name: username,
    avatar_color: '#' + Math.floor(Math.random()*16777215).toString(16),
    avatar_url: '',
    about: ''
  };
  users.push(newUser);
  const token = jwt.sign({ id: newUser.id }, JWT_SECRET);
  res.json({ token, user: { id: newUser.id, username: newUser.username, display_name: newUser.display_name, avatar_color: newUser.avatar_color, avatar_url: newUser.avatar_url, about: newUser.about } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id }, JWT_SECRET);
  res.json({ token, user: { id: user.id, username: user.username, display_name: user.display_name, avatar_color: user.avatar_color, avatar_url: user.avatar_url, about: user.about } });
});

// User API
app.get('/api/users/me', auth, (req, res) => {
  res.json(req.user);
});

app.put('/api/users/me', auth, (req, res) => {
  const { display_name, username, about, avatar_color, avatar_url } = req.body;
  if (username) req.user.username = username;
  req.user.display_name = display_name || req.user.display_name;
  req.user.about = about || '';
  req.user.avatar_color = avatar_color || req.user.avatar_color;
  req.user.avatar_url = avatar_url || '';
  res.json(req.user);
});

app.put('/api/users/me/password', auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!await bcrypt.compare(oldPassword, req.user.password)) return res.status(400).json({ error: 'Wrong old password' });
  req.user.password = await bcrypt.hash(newPassword, 10);
  res.json({ success: true });
});

app.delete('/api/users/me', auth, (req, res) => {
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx > -1) users.splice(idx, 1);
  res.json({ success: true });
});

app.get('/api/users/search', auth, (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  if (!q) return res.json([]);
  const result = users.filter(u => u.id !== req.user.id && u.username.toLowerCase().includes(q))
    .slice(0, 10).map(u => ({ id: u.id, username: u.username, avatar_color: u.avatar_color, avatar_url: u.avatar_url }));
  res.json(result);
});

app.get('/api/users/:id', auth, (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ id: user.id, username: user.username, display_name: user.display_name, avatar_color: user.avatar_color, avatar_url: user.avatar_url, about: user.about });
});

// Friends
app.get('/api/friends', auth, (req, res) => {
  const userFriends = friends.filter(f => (f.user1 === req.user.id || f.user2 === req.user.id));
  const list = userFriends.map(f => {
    const otherId = f.user1 === req.user.id ? f.user2 : f.user1;
    const otherUser = users.find(u => u.id === otherId);
    if (!otherUser) return null;
    return { id: otherUser.id, username: otherUser.username, avatar_color: otherUser.avatar_color, avatar_url: otherUser.avatar_url, status: f.status, sender: f.senderId === req.user.id ? 'me' : 'them' };
  }).filter(Boolean);
  res.json(list);
});

app.post('/api/friends/request', auth, (req, res) => {
  const friendId = req.body.friendId;
  if (friendId === req.user.id) return res.status(400).json({ error: 'Cannot add yourself' });
  const existing = friends.find(f => (f.user1 === req.user.id && f.user2 === friendId) || (f.user1 === friendId && f.user2 === req.user.id));
  if (existing) return res.status(400).json({ error: 'Already friends or pending' });
  friends.push({ user1: req.user.id, user2: friendId, status: 'pending', senderId: req.user.id });
  // Notify via socket
  const targetSocket = Object.values(io.sockets.sockets).find(s => s.userId === friendId);
  if (targetSocket) targetSocket.emit('friend-request', { from: req.user.id });
  res.json({ success: true });
});

app.post('/api/friends/accept', auth, (req, res) => {
  const friendId = req.body.friendId;
  const f = friends.find(f => (f.user1 === req.user.id && f.user2 === friendId && f.status === 'pending' && f.senderId !== req.user.id)
    || (f.user1 === friendId && f.user2 === req.user.id && f.status === 'pending' && f.senderId !== req.user.id));
  if (!f) return res.status(404).json({ error: 'No pending request' });
  f.status = 'accepted';
  const otherId = f.user1 === req.user.id ? f.user2 : f.user1;
  const otherSocket = Object.values(io.sockets.sockets).find(s => s.userId === otherId);
  if (otherSocket) otherSocket.emit('friend-update', {});
  res.json({ success: true });
});

app.post('/api/friends/remove', auth, (req, res) => {
  const friendId = req.body.friendId;
  const idx = friends.findIndex(f => (f.user1 === req.user.id && f.user2 === friendId) || (f.user1 === friendId && f.user2 === req.user.id));
  if (idx > -1) friends.splice(idx, 1);
  res.json({ success: true });
});

app.post('/api/friends/block', auth, (req, res) => {
  const friendId = req.body.friendId;
  if (!blocked.find(b => b.user === req.user.id && b.blocked === friendId)) {
    blocked.push({ user: req.user.id, blocked: friendId });
  }
  res.json({ success: true });
});

// Servers
app.get('/api/servers', auth, (req, res) => {
  const userServers = servers.filter(s => s.members.includes(req.user.id));
  res.json(userServers.map(s => ({ id: s.id, name: s.name, description: s.description, avatar_url: s.avatar_url, owner_id: s.owner_id, invite_code: s.invite_code })));
});

app.post('/api/servers', auth, (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const server = {
    id: generateId(),
    name,
    description: description || '',
    avatar_url: '',
    owner_id: req.user.id,
    members: [req.user.id],
    invite_code: uuidv4().slice(0, 8)
  };
  servers.push(server);
  // Create default category
  const catId = generateId();
  categories.push({ id: catId, server_id: server.id, name: 'General' });
  channels.push({ id: generateId(), server_id: server.id, category_id: catId, name: 'general', type: 'text', slowmode: 0, is_private: false });
  res.json(server);
});

app.post('/api/servers/join', auth, (req, res) => {
  const { inviteCode } = req.body;
  const server = servers.find(s => s.invite_code === inviteCode);
  if (!server) return res.status(404).json({ error: 'Invalid invite' });
  if (server.members.includes(req.user.id)) return res.json({ success: true });
  server.members.push(req.user.id);
  res.json({ success: true });
});

app.get('/api/servers/:id/categories', auth, (req, res) => {
  const serverId = parseInt(req.params.id);
  const cats = categories.filter(c => c.server_id === serverId);
  const chs = channels.filter(ch => ch.server_id === serverId);
  const result = cats.map(c => ({
    id: c.id,
    name: c.name,
    channels: chs.filter(ch => ch.category_id === c.id).map(ch => ({ id: ch.id, name: ch.name, type: ch.type, slowmode: ch.slowmode, is_private: ch.is_private }))
  }));
  // also channels with null category
  const noCat = chs.filter(ch => ch.category_id === null);
  if (noCat.length) result.push({ id: null, name: 'Uncategorized', channels: noCat });
  res.json(result);
});

app.post('/api/servers/:id/categories', auth, (req, res) => {
  const serverId = parseInt(req.params.id);
  const server = servers.find(s => s.id === serverId && s.owner_id === req.user.id);
  if (!server) return res.status(403).json({ error: 'Not owner' });
  const cat = { id: generateId(), server_id: serverId, name: req.body.name };
  categories.push(cat);
  res.json(cat);
});

app.get('/api/servers/:id/members', auth, (req, res) => {
  const server = servers.find(s => s.id === parseInt(req.params.id));
  if (!server || !server.members.includes(req.user.id)) return res.status(403).json({ error: 'Not a member' });
  const memberUsers = users.filter(u => server.members.includes(u.id));
  res.json(memberUsers.map(u => ({
    id: u.id, username: u.username, avatar_color: u.avatar_color, avatar_url: u.avatar_url,
    role: u.id === server.owner_id ? 'owner' : 'member'
  })));
});

app.post('/api/servers/:id/kick/:userId', auth, (req, res) => {
  const server = servers.find(s => s.id === parseInt(req.params.id) && s.owner_id === req.user.id);
  if (!server) return res.status(403).json({ error: 'Not owner' });
  server.members = server.members.filter(m => m !== parseInt(req.params.userId));
  res.json({ success: true });
});

app.post('/api/servers/:id/ban/:userId', auth, (req, res) => {
  const server = servers.find(s => s.id === parseInt(req.params.id) && s.owner_id === req.user.id);
  if (!server) return res.status(403).json({ error: 'Not owner' });
  server.members = server.members.filter(m => m !== parseInt(req.params.userId));
  res.json({ success: true });
});

app.put('/api/servers/:id/members/:userId/role', auth, (req, res) => {
  const server = servers.find(s => s.id === parseInt(req.params.id) && s.owner_id === req.user.id);
  if (!server) return res.status(403).json({ error: 'Not owner' });
  res.json({ success: true }); // simplified, just for front
});

app.put('/api/servers/:id', auth, (req, res) => {
  const server = servers.find(s => s.id === parseInt(req.params.id) && s.owner_id === req.user.id);
  if (!server) return res.status(403).json({ error: 'Not owner' });
  server.name = req.body.name || server.name;
  server.description = req.body.description || '';
  server.avatar_url = req.body.avatar_url || '';
  res.json(server);
});

app.post('/api/servers/:id/invite/regenerate', auth, (req, res) => {
  const server = servers.find(s => s.id === parseInt(req.params.id) && s.owner_id === req.user.id);
  if (!server) return res.status(403).json({ error: 'Not owner' });
  server.invite_code = uuidv4().slice(0, 8);
  res.json({ invite_code: server.invite_code });
});

app.delete('/api/servers/:id', auth, (req, res) => {
  const idx = servers.findIndex(s => s.id === parseInt(req.params.id) && s.owner_id === req.user.id);
  if (idx === -1) return res.status(403).json({ error: 'Not owner' });
  servers.splice(idx, 1);
  res.json({ success: true });
});

// Channels
app.post('/api/servers/:id/channels', auth, (req, res) => {
  const serverId = parseInt(req.params.id);
  const server = servers.find(s => s.id === serverId && s.owner_id === req.user.id);
  if (!server) return res.status(403).json({ error: 'Not owner' });
  const { name, type, category_id } = req.body;
  const channel = { id: generateId(), server_id: serverId, category_id: category_id || null, name, type: type || 'text', slowmode: 0, is_private: false };
  channels.push(channel);
  res.json(channel);
});

app.get('/api/channels/:id/messages', auth, (req, res) => {
  const channelId = parseInt(req.params.id);
  const channelMessages = messages.filter(m => m.channel_id === channelId);
  const result = channelMessages.map(m => {
    const user = users.find(u => u.id === m.user_id);
    return { id: m.id, channel_id: m.channel_id, user_id: m.user_id, username: user?.username, avatar_color: user?.avatar_color, avatar_url: user?.avatar_url, content: m.content, timestamp: m.timestamp, replied_to: m.replied_to };
  });
  res.json(result);
});

app.delete('/api/channels/:id', auth, (req, res) => {
  const channelId = parseInt(req.params.id);
  const ch = channels.find(c => c.id === channelId);
  if (!ch) return res.status(404).json({ error: 'Not found' });
  const server = servers.find(s => s.id === ch.server_id && s.owner_id === req.user.id);
  if (!server) return res.status(403).json({ error: 'Not owner' });
  channels = channels.filter(c => c.id !== channelId);
  res.json({ success: true });
});

app.put('/api/channels/:id', auth, (req, res) => {
  const channel = channels.find(c => c.id === parseInt(req.params.id));
  if (!channel) return res.status(404).json({ error: 'Not found' });
  channel.name = req.body.name || channel.name;
  channel.slowmode = req.body.slowmode || 0;
  channel.is_private = req.body.is_private || false;
  res.json(channel);
});

app.get('/api/channels/:id/permissions', auth, (req, res) => {
  // simplified
  res.json([]);
});
app.post('/api/channels/:id/permissions', auth, (req, res) => {
  res.json({ success: true });
});
app.delete('/api/channels/:id/permissions/:userId', auth, (req, res) => {
  res.json({ success: true });
});

// DM messages
app.get('/api/dm/:friendId', auth, (req, res) => {
  const friendId = parseInt(req.params.friendId);
  const room = [req.user.id, friendId].sort().join('-');
  const msgs = dmMessages.filter(m => m.room === room);
  const result = msgs.map(m => {
    const user = users.find(u => u.id === m.sender_id);
    return { id: m.id, sender_id: m.sender_id, username: user?.username, avatar_color: user?.avatar_color, avatar_url: user?.avatar_url, content: m.content, timestamp: m.timestamp, replied_to: m.replied_to };
  });
  res.json(result);
});

// Groups
app.get('/api/groups', auth, (req, res) => {
  const userGroups = groups.filter(g => g.members.includes(req.user.id));
  res.json(userGroups.map(g => ({ id: g.id, name: g.name, avatar_color: g.avatar_color, owner_id: g.owner_id })));
});

app.post('/api/groups', auth, (req, res) => {
  const { name, memberIds } = req.body;
  const group = {
    id: generateId(),
    name,
    avatar_color: '#' + Math.floor(Math.random()*16777215).toString(16),
    owner_id: req.user.id,
    members: [req.user.id, ...(memberIds || [])],
    invite_code: uuidv4().slice(0, 8)
  };
  groups.push(group);
  res.json(group);
});

app.get('/api/groups/:id/messages', auth, (req, res) => {
  const groupId = parseInt(req.params.id);
  const msgs = groupMessages.filter(m => m.group_id === groupId);
  const result = msgs.map(m => {
    const user = users.find(u => u.id === m.sender_id);
    return { id: m.id, sender_id: m.sender_id, username: user?.username, avatar_color: user?.avatar_color, avatar_url: user?.avatar_url, content: m.content, timestamp: m.timestamp, replied_to: m.replied_to };
  });
  res.json(result);
});

app.get('/api/groups/:id/members', auth, (req, res) => {
  const group = groups.find(g => g.id === parseInt(req.params.id));
  if (!group) return res.status(404).json({ error: 'Not found' });
  const memberUsers = users.filter(u => group.members.includes(u.id));
  res.json(memberUsers.map(u => ({ id: u.id, username: u.username, avatar_color: u.avatar_color, avatar_url: u.avatar_url })));
});

app.post('/api/groups/:id/invite', auth, (req, res) => {
  const group = groups.find(g => g.id === parseInt(req.params.id) && g.owner_id === req.user.id);
  if (!group) return res.status(403).json({ error: 'Not owner' });
  res.json({ invite_code: group.invite_code });
});

app.delete('/api/groups/:id/members/:userId', auth, (req, res) => {
  const group = groups.find(g => g.id === parseInt(req.params.id) && (g.owner_id === req.user.id || req.user.id === parseInt(req.params.userId)));
  if (!group) return res.status(403).json({ error: 'Not allowed' });
  group.members = group.members.filter(m => m !== parseInt(req.params.userId));
  res.json({ success: true });
});

app.delete('/api/groups/:id', auth, (req, res) => {
  const idx = groups.findIndex(g => g.id === parseInt(req.params.id) && g.owner_id === req.user.id);
  if (idx === -1) return res.status(403).json({ error: 'Not owner' });
  groups.splice(idx, 1);
  res.json({ success: true });
});

// Message edit/delete/pin
app.put('/api/messages/:id', auth, (req, res) => {
  const msgId = parseInt(req.params.id);
  const msg = [...messages, ...dmMessages, ...groupMessages].find(m => m.id === msgId);
  if (!msg || msg.user_id !== req.user.id) return res.status(403).json({ error: 'Not allowed' });
  msg.content = req.body.content;
  res.json({ success: true });
});

app.delete('/api/messages/:id', auth, (req, res) => {
  messages = messages.filter(m => m.id !== parseInt(req.params.id));
  res.json({ success: true });
});
app.delete('/api/messages/dm/:id', auth, (req, res) => {
  dmMessages = dmMessages.filter(m => m.id !== parseInt(req.params.id));
  res.json({ success: true });
});
app.delete('/api/messages/group/:id', auth, (req, res) => {
  groupMessages = groupMessages.filter(m => m.id !== parseInt(req.params.id));
  res.json({ success: true });
});
app.post('/api/messages/:id/pin', auth, (req, res) => {
  res.json({ success: true });
});

// Socket.IO
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = users.find(u => u.id === payload.id);
    if (!user) return next(new Error('User not found'));
    socket.userId = user.id;
    next();
  } catch (e) { next(new Error('Invalid token')); }
});

io.on('connection', (socket) => {
  socket.join('user-' + socket.userId);

  socket.on('dm-join', (friendId) => {
    const room = [socket.userId, friendId].sort().join('-');
    socket.join(room);
  });

  socket.on('dm-message', (data) => {
    const { friendId, content, repliedTo } = data;
    const msgId = generateId();
    const room = [socket.userId, friendId].sort().join('-');
    const msg = { id: msgId, room, sender_id: socket.userId, content, timestamp: new Date().toISOString(), replied_to: repliedTo || null };
    dmMessages.push(msg);
    const sender = users.find(u => u.id === socket.userId);
    io.to(room).emit('dm-message', { id: msgId, sender_id: socket.userId, username: sender.username, avatar_color: sender.avatar_color, avatar_url: sender.avatar_url, content, timestamp: msg.timestamp, replied_to: msg.replied_to });
  });

  socket.on('group-join', (groupId) => {
    socket.join('group-' + groupId);
  });

  socket.on('group-message', (data) => {
    const { groupId, content, repliedTo } = data;
    const msgId = generateId();
    const group = groups.find(g => g.id === groupId);
    if (!group || !group.members.includes(socket.userId)) return;
    const msg = { id: msgId, group_id: groupId, sender_id: socket.userId, content, timestamp: new Date().toISOString(), replied_to: repliedTo || null };
    groupMessages.push(msg);
    const sender = users.find(u => u.id === socket.userId);
    io.to('group-' + groupId).emit('group-message', { id: msgId, sender_id: socket.userId, username: sender.username, avatar_color: sender.avatar_color, avatar_url: sender.avatar_url, content, timestamp: msg.timestamp, replied_to: msg.replied_to });
  });

  socket.on('join-channel', (channelId) => {
    socket.join('channel-' + channelId);
  });

  socket.on('send-message', (data) => {
    const { channelId, content, repliedTo } = data;
    const ch = channels.find(c => c.id === channelId);
    if (!ch) return;
    const msgId = generateId();
    const msg = { id: msgId, channel_id: channelId, user_id: socket.userId, content, timestamp: new Date().toISOString(), replied_to: repliedTo || null };
    messages.push(msg);
    const sender = users.find(u => u.id === socket.userId);
    io.to('channel-' + channelId).emit('new-message', { id: msgId, channel_id: channelId, user_id: socket.userId, username: sender.username, avatar_color: sender.avatar_color, avatar_url: sender.avatar_url, content, timestamp: msg.timestamp, replied_to: msg.replied_to });
  });

  // Calls (relay only)
  socket.on('call-join', (room) => {
    socket.join(room);
    socket.to(room).emit('call-join', socket.userId);
  });
  socket.on('call-offer', (data) => { socket.to(data.room).emit('call-offer', { from: socket.userId, offer: data.offer }); });
  socket.on('call-answer', (data) => { socket.to(data.room).emit('call-answer', { from: socket.userId, answer: data.answer }); });
  socket.on('call-candidate', (data) => { socket.to(data.room).emit('call-candidate', { from: socket.userId, candidate: data.candidate }); });
  socket.on('call-leave', (room) => {
    socket.to(room).emit('call-leave', socket.userId);
    socket.leave(room);
  });

  socket.on('disconnect', () => {});
});

server.listen(3000, () => {
  console.log('Server running on port 3000');
});