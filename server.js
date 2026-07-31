const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'votex_jwt_secret_replace_me';
const SALT_ROUNDS = 10;
const MAX_GROUP_MEMBERS = 30;

app.use(express.json());
app.use(express.static(__dirname));

const db = new sqlite3.Database('./votex.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT,
    password TEXT NOT NULL,
    avatar_color TEXT DEFAULT '#5865f2',
    avatar_url TEXT DEFAULT '',
    about TEXT DEFAULT ''
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS friendships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    friend_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    UNIQUE(user_id, friend_id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    owner_id INTEGER NOT NULL,
    invite_code TEXT UNIQUE NOT NULL,
    avatar_url TEXT DEFAULT '',
    FOREIGN KEY(owner_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS server_members (
    user_id INTEGER NOT NULL,
    server_id TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    PRIMARY KEY(user_id, server_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(server_id) REFERENCES servers(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    server_id TEXT NOT NULL,
    position INTEGER DEFAULT 0,
    FOREIGN KEY(server_id) REFERENCES servers(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    server_id TEXT NOT NULL,
    category_id INTEGER,
    type TEXT DEFAULT 'text',
    FOREIGN KEY(server_id) REFERENCES servers(id),
    FOREIGN KEY(category_id) REFERENCES categories(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id INTEGER,
    sender_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    dm_recipient_id INTEGER,
    group_id INTEGER,
    replied_to INTEGER,
    pinned INTEGER DEFAULT 0,
    FOREIGN KEY(channel_id) REFERENCES channels(id),
    FOREIGN KEY(sender_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    invite_code TEXT UNIQUE NOT NULL,
    avatar_color TEXT DEFAULT '#5865f2',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS group_members (
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(user_id, group_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(group_id) REFERENCES groups(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    user_agent TEXT,
    ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

const onlineUsers = new Map();

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.sendStatus(403);
    req.user = decoded;
    req.token = token;
    db.run(`UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE token = ?`, [token]);
    next();
  });
}

function generateInviteCode() {
  return uuidv4().substring(0, 8);
}

function isBlocked(userA, userB, callback) {
  db.get(`SELECT 1 FROM friendships WHERE
    (user_id = ? AND friend_id = ? AND status = 'blocked') OR
    (user_id = ? AND friend_id = ? AND status = 'blocked')`,
    [userA, userB, userB, userA], (err, row) => {
      callback(!!row);
    });
}

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const hash = bcrypt.hashSync(password, SALT_ROUNDS);
  db.run(`INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)`, [username, hash, username], function(err) {
    if (err) return res.status(400).json({ error: 'User already exists' });
    const token = jwt.sign({ id: this.lastID, username }, JWT_SECRET);
    db.run(`INSERT INTO sessions (id, user_id, token, user_agent, ip) VALUES (?, ?, ?, ?, ?)`,
      [uuidv4(), this.lastID, token, req.headers['user-agent'] || '', req.ip]);
    res.json({ token, user: { id: this.lastID, username } });
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
    db.run(`INSERT INTO sessions (id, user_id, token, user_agent, ip) VALUES (?, ?, ?, ?, ?)`,
      [uuidv4(), user.id, token, req.headers['user-agent'] || '', req.ip]);
    res.json({ token, user: { id: user.id, username: user.username, display_name: user.display_name, avatar_color: user.avatar_color, avatar_url: user.avatar_url, about: user.about } });
  });
});

app.post('/api/logout', authenticateToken, (req, res) => {
  db.run(`DELETE FROM sessions WHERE token = ?`, [req.token], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.get('/api/users/me', authenticateToken, (req, res) => {
  db.get(`SELECT id, username, display_name, avatar_color, avatar_url, about FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(user);
  });
});

app.put('/api/users/me', authenticateToken, (req, res) => {
  const { display_name, username, about, avatar_color, avatar_url } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });
  db.run(`UPDATE users SET display_name = ?, username = ?, about = ?, avatar_color = ?, avatar_url = ? WHERE id = ?`,
    [display_name || username, username, about || '', avatar_color || '#5865f2', avatar_url || '', req.user.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
});

app.put('/api/users/me/password', authenticateToken, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Old and new password required' });
  db.get(`SELECT password FROM users WHERE id = ?`, [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!bcrypt.compareSync(oldPassword, row.password)) return res.status(400).json({ error: 'Invalid old password' });
    const hash = bcrypt.hashSync(newPassword, SALT_ROUNDS);
    db.run(`UPDATE users SET password = ? WHERE id = ?`, [hash, req.user.id], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

app.delete('/api/users/me', authenticateToken, (req, res) => {
  db.run(`DELETE FROM sessions WHERE user_id = ?`, [req.user.id]);
  db.run(`DELETE FROM users WHERE id = ?`, [req.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.get('/api/users/search', authenticateToken, (req, res) => {
  const q = req.query.q || '';
  db.all(`SELECT id, username, display_name, avatar_color, avatar_url FROM users WHERE username LIKE ? OR display_name LIKE ? LIMIT 20`,
    [`%${q}%`, `%${q}%`], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
});

app.get('/api/users/:id', authenticateToken, (req, res) => {
  db.get(`SELECT id, username, display_name, avatar_color, avatar_url, about FROM users WHERE id = ?`, [req.params.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

app.post('/api/friends/request', authenticateToken, (req, res) => {
  const { friendId } = req.body;
  if (req.user.id == friendId) return res.status(400).json({ error: 'Cannot friend yourself' });
  isBlocked(req.user.id, friendId, (blocked) => {
    if (blocked) return res.status(403).json({ error: 'Cannot friend blocked user' });
    db.run(`INSERT OR IGNORE INTO friendships (user_id, friend_id, status) VALUES (?, ?, 'pending')`,
      [req.user.id, friendId], function(err) {
        if (err) return res.status(400).json({ error: 'Already sent or friends' });
        // emit real-time event to recipient
        const recipientSocket = onlineUsers.get(friendId);
        if (recipientSocket) {
          io.to(recipientSocket).emit('friend-request', { from: req.user.id });
        }
        res.json({ success: true });
      });
  });
});

app.post('/api/friends/accept', authenticateToken, (req, res) => {
  const { friendId } = req.body;
  db.run(`UPDATE friendships SET status = 'accepted' WHERE user_id = ? AND friend_id = ? AND status = 'pending'`,
    [friendId, req.user.id], function(err) {
      if (err || this.changes === 0) return res.status(400).json({ error: 'No pending request' });
      db.run(`INSERT OR IGNORE INTO friendships (user_id, friend_id, status) VALUES (?, ?, 'accepted')`,
        [req.user.id, friendId]);
      const senderSocket = onlineUsers.get(friendId);
      if (senderSocket) io.to(senderSocket).emit('friend-update', {});
      res.json({ success: true });
    });
});

app.post('/api/friends/remove', authenticateToken, (req, res) => {
  const { friendId } = req.body;
  db.run(`DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)`,
    [req.user.id, friendId, friendId, req.user.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      const otherSocket = onlineUsers.get(friendId);
      if (otherSocket) io.to(otherSocket).emit('friend-update', {});
      res.json({ success: true });
    });
});

app.post('/api/friends/block', authenticateToken, (req, res) => {
  const { friendId } = req.body;
  db.run(`DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)`,
    [req.user.id, friendId, friendId, req.user.id]);
  db.run(`INSERT OR REPLACE INTO friendships (user_id, friend_id, status) VALUES (?, ?, 'blocked')`,
    [req.user.id, friendId], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      const otherSocket = onlineUsers.get(friendId);
      if (otherSocket) io.to(otherSocket).emit('friend-update', {});
      res.json({ success: true });
    });
});

app.post('/api/friends/unblock', authenticateToken, (req, res) => {
  const { friendId } = req.body;
  db.run(`DELETE FROM friendships WHERE user_id = ? AND friend_id = ? AND status = 'blocked'`,
    [req.user.id, friendId], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      const otherSocket = onlineUsers.get(friendId);
      if (otherSocket) io.to(otherSocket).emit('friend-update', {});
      res.json({ success: true });
    });
});

app.get('/api/friends', authenticateToken, (req, res) => {
  db.all(`SELECT u.id, u.username, u.display_name, u.avatar_color, u.avatar_url, f.status, f.user_id as sender_id
          FROM friendships f
          JOIN users u ON (CASE WHEN f.user_id = ? THEN f.friend_id ELSE f.user_id END) = u.id
          WHERE (f.user_id = ? OR f.friend_id = ?) AND (f.status = 'accepted' OR (f.status = 'pending' AND f.friend_id = ?))
          ORDER BY u.username`,
    [req.user.id, req.user.id, req.user.id, req.user.id], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      const friends = rows.map(r => ({
        id: r.id,
        username: r.username,
        display_name: r.display_name,
        avatar_color: r.avatar_color,
        avatar_url: r.avatar_url,
        status: r.status,
        sender: r.sender_id === req.user.id ? 'me' : 'them'
      }));
      res.json(friends);
    });
});

app.get('/api/friends/blocked', authenticateToken, (req, res) => {
  db.all(`SELECT u.id, u.username, u.display_name, u.avatar_color, u.avatar_url FROM friendships f
          JOIN users u ON f.friend_id = u.id
          WHERE f.user_id = ? AND f.status = 'blocked'`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/servers', authenticateToken, (req, res) => {
  db.all(`SELECT s.id, s.name, s.description, s.owner_id, s.invite_code, s.avatar_url, sm.role
          FROM servers s
          JOIN server_members sm ON s.id = sm.server_id
          WHERE sm.user_id = ?
          ORDER BY s.name`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/servers', authenticateToken, (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Server name required' });
  const id = uuidv4();
  const invite = generateInviteCode();
  db.run(`INSERT INTO servers (id, name, description, owner_id, invite_code) VALUES (?, ?, ?, ?, ?)`,
    [id, name, description || '', req.user.id, invite], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      db.run(`INSERT INTO server_members (user_id, server_id, role) VALUES (?, ?, 'owner')`, [req.user.id, id]);
      db.run(`INSERT INTO categories (name, server_id, position) VALUES ('Text Channels', ?, 0)`, [id], function() {
        const catId = this.lastID;
        db.run(`INSERT INTO channels (name, server_id, category_id, type) VALUES ('general', ?, ?, 'text')`, [id, catId]);
      });
      res.json({ id, name, description, invite_code: invite, role: 'owner' });
    });
});

app.post('/api/servers/join', authenticateToken, (req, res) => {
  const { inviteCode } = req.body;
  db.get(`SELECT * FROM servers WHERE invite_code = ?`, [inviteCode], (err, server) => {
    if (!server) return res.status(404).json({ error: 'Invalid invite' });
    db.run(`INSERT OR IGNORE INTO server_members (user_id, server_id) VALUES (?, ?)`, [req.user.id, server.id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(400).json({ error: 'Already a member' });
      res.json({ success: true, serverId: server.id });
    });
  });
});

app.get('/api/servers/:id/invite', authenticateToken, (req, res) => {
  db.get(`SELECT invite_code FROM servers WHERE id = ?`, [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Server not found' });
    res.json({ invite_code: row.invite_code });
  });
});

app.delete('/api/servers/:id', authenticateToken, (req, res) => {
  db.get(`SELECT * FROM server_members WHERE server_id = ? AND user_id = ? AND role = 'owner'`, [req.params.id, req.user.id], (err, row) => {
    if (!row) return res.status(403).json({ error: 'Only owner can delete' });
    db.run(`DELETE FROM servers WHERE id = ?`, [req.params.id]);
    res.json({ success: true });
  });
});

app.post('/api/servers/:id/leave', authenticateToken, (req, res) => {
  db.run(`DELETE FROM server_members WHERE server_id = ? AND user_id = ?`, [req.params.id, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.get('/api/servers/:id/members', authenticateToken, (req, res) => {
  db.all(`SELECT u.id, u.username, u.display_name, u.avatar_color, u.avatar_url, sm.role
          FROM server_members sm JOIN users u ON sm.user_id = u.id
          WHERE sm.server_id = ?`, [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.delete('/api/servers/:id/members/:userId', authenticateToken, (req, res) => {
  const serverId = req.params.id;
  const userId = req.params.userId;
  db.get(`SELECT role FROM server_members WHERE server_id = ? AND user_id = ?`, [serverId, req.user.id], (err, row) => {
    if (!row || (row.role !== 'owner' && userId != req.user.id)) return res.status(403).json({ error: 'Not allowed' });
    db.run(`DELETE FROM server_members WHERE server_id = ? AND user_id = ?`, [serverId, userId], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

app.get('/api/servers/:id/categories', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM categories WHERE server_id = ? ORDER BY position`, [req.params.id], (err, cats) => {
    if (err) return res.status(500).json({ error: err.message });
    const catIds = cats.map(c => c.id);
    if (catIds.length === 0) return res.json([]);
    const placeholders = catIds.map(() => '?').join(',');
    db.all(`SELECT * FROM channels WHERE server_id = ? AND (category_id IN (${placeholders}) OR category_id IS NULL) ORDER BY category_id, name`,
      [req.params.id, ...catIds], (err, channels) => {
        if (err) return res.status(500).json({ error: err.message });
        const result = cats.map(cat => ({
          ...cat,
          channels: channels.filter(ch => ch.category_id === cat.id)
        }));
        const uncategorised = channels.filter(ch => ch.category_id === null);
        if (uncategorised.length) result.push({ id: null, name: 'Uncategorised', channels: uncategorised });
        res.json(result);
    });
  });
});

app.post('/api/servers/:id/categories', authenticateToken, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Category name required' });
  db.run(`INSERT INTO categories (name, server_id) VALUES (?, ?)`, [name, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, name });
  });
});

app.post('/api/servers/:id/channels', authenticateToken, (req, res) => {
  const { name, category_id, type } = req.body;
  if (!name) return res.status(400).json({ error: 'Channel name required' });
  db.run(`INSERT INTO channels (name, server_id, category_id, type) VALUES (?, ?, ?, ?)`,
    [name, req.params.id, category_id || null, type || 'text'], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, name, category_id, type: type || 'text' });
    });
});

app.delete('/api/channels/:id', authenticateToken, (req, res) => {
  const chId = req.params.id;
  db.get(`SELECT c.server_id FROM channels c JOIN servers s ON c.server_id = s.id WHERE c.id = ? AND s.owner_id = ?`, [chId, req.user.id], (err, row) => {
    if (!row) return res.status(403).json({ error: 'Only server owner can delete channels' });
    db.run(`DELETE FROM channels WHERE id = ?`, [chId], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

app.get('/api/channels/:id/messages', authenticateToken, (req, res) => {
  const limit = req.query.limit || 50;
  db.all(`SELECT m.id, m.content, m.timestamp, m.replied_to, m.pinned,
          u.id as user_id, u.username, u.display_name, u.avatar_color, u.avatar_url
          FROM messages m JOIN users u ON m.sender_id = u.id
          WHERE m.channel_id = ? AND m.dm_recipient_id IS NULL AND m.group_id IS NULL
          ORDER BY m.timestamp ASC LIMIT ?`, [req.params.id, limit], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.put('/api/messages/:id', authenticateToken, (req, res) => {
  const msgId = req.params.id;
  const { content } = req.body;
  db.get(`SELECT sender_id FROM messages WHERE id = ?`, [msgId], (err, msg) => {
    if (err || !msg) return res.status(404).json({ error: 'Message not found' });
    if (msg.sender_id !== req.user.id) return res.status(403).json({ error: 'Not allowed' });
    db.run(`UPDATE messages SET content = ? WHERE id = ?`, [content, msgId], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

app.post('/api/messages/:id/pin', authenticateToken, (req, res) => {
  const msgId = req.params.id;
  db.run(`UPDATE messages SET pinned = CASE WHEN pinned = 0 THEN 1 ELSE 0 END WHERE id = ?`, [msgId], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.delete('/api/messages/:id', authenticateToken, (req, res) => {
  const msgId = req.params.id;
  db.get(`SELECT m.*, s.owner_id as server_owner FROM messages m
          LEFT JOIN channels c ON m.channel_id = c.id
          LEFT JOIN servers s ON c.server_id = s.id
          WHERE m.id = ?`, [msgId], (err, msg) => {
    if (err || !msg) return res.status(404).json({ error: 'Message not found' });
    if (msg.sender_id !== req.user.id && (!msg.server_owner || msg.server_owner !== req.user.id)) {
      return res.status(403).json({ error: 'Not allowed' });
    }
    db.run(`DELETE FROM messages WHERE id = ?`, [msgId], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

app.get('/api/dm/:friendId', authenticateToken, (req, res) => {
  const friendId = req.params.friendId;
  db.get(`SELECT 1 FROM friendships WHERE
          ((user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)) AND status = 'accepted'`,
    [req.user.id, friendId, friendId, req.user.id], (err, row) => {
      if (!row) return res.status(403).json({ error: 'Not friends' });
      isBlocked(req.user.id, friendId, (blocked) => {
        if (blocked) return res.status(403).json({ error: 'Cannot DM a blocked user' });
        db.all(`SELECT m.id, m.content, m.timestamp, m.replied_to, u.id as user_id, u.username, u.display_name, u.avatar_color, u.avatar_url
                FROM messages m JOIN users u ON m.sender_id = u.id
                WHERE (m.sender_id = ? AND m.dm_recipient_id = ?) OR (m.sender_id = ? AND m.dm_recipient_id = ?)
                ORDER BY m.timestamp ASC LIMIT 100`,
          [req.user.id, friendId, friendId, req.user.id], (err, msgs) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(msgs);
        });
      });
  });
});

app.delete('/api/messages/dm/:id', authenticateToken, (req, res) => {
  const msgId = req.params.id;
  db.get(`SELECT * FROM messages WHERE id = ? AND dm_recipient_id IS NOT NULL`, [msgId], (err, msg) => {
    if (err || !msg) return res.status(404).json({ error: 'Message not found' });
    if (msg.sender_id !== req.user.id) return res.status(403).json({ error: 'Not allowed' });
    db.run(`DELETE FROM messages WHERE id = ?`, [msgId], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

app.post('/api/groups', authenticateToken, (req, res) => {
  const { name, memberIds } = req.body;
  if (!name) return res.status(400).json({ error: 'Group name required' });
  if (!memberIds || !Array.isArray(memberIds) || memberIds.length === 0) {
    return res.status(400).json({ error: 'At least one member required' });
  }
  if (memberIds.length > MAX_GROUP_MEMBERS - 1) return res.status(400).json({ error: 'Too many members' });
  const invite = generateInviteCode();
  db.run(`INSERT INTO groups (name, owner_id, invite_code) VALUES (?, ?, ?)`, [name, req.user.id, invite], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    const groupId = this.lastID;
    db.run(`INSERT INTO group_members (user_id, group_id) VALUES (?, ?)`, [req.user.id, groupId]);
    const placeholders = memberIds.map(() => '(?,?)').join(',');
    const values = [];
    memberIds.forEach(id => { values.push(id, groupId); });
    db.run(`INSERT OR IGNORE INTO group_members (user_id, group_id) VALUES ${placeholders}`, values, (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ id: groupId, name, invite_code: invite });
    });
  });
});

app.get('/api/groups', authenticateToken, (req, res) => {
  db.all(`SELECT g.id, g.name, g.owner_id, g.invite_code, g.avatar_color
          FROM groups g
          JOIN group_members gm ON g.id = gm.group_id
          WHERE gm.user_id = ?
          ORDER BY g.name`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/groups/:id/messages', authenticateToken, (req, res) => {
  const groupId = req.params.id;
  db.get(`SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?`, [groupId, req.user.id], (err, row) => {
    if (!row) return res.status(403).json({ error: 'Not a member' });
    db.all(`SELECT m.id, m.content, m.timestamp, m.replied_to, u.id as sender_id, u.username, u.display_name, u.avatar_color, u.avatar_url
            FROM messages m JOIN users u ON m.sender_id = u.id
            WHERE m.group_id = ?
            ORDER BY m.timestamp ASC LIMIT 100`, [groupId], (err2, msgs) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json(msgs);
    });
  });
});

app.delete('/api/messages/group/:id', authenticateToken, (req, res) => {
  const msgId = req.params.id;
  db.get(`SELECT m.*, g.owner_id FROM messages m
          LEFT JOIN groups g ON m.group_id = g.id
          WHERE m.id = ?`, [msgId], (err, msg) => {
    if (err || !msg) return res.status(404).json({ error: 'Message not found' });
    if (msg.sender_id !== req.user.id && (!msg.owner_id || msg.owner_id !== req.user.id)) {
      return res.status(403).json({ error: 'Not allowed' });
    }
    db.run(`DELETE FROM messages WHERE id = ?`, [msgId], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

app.get('/api/groups/:id/members', authenticateToken, (req, res) => {
  const groupId = req.params.id;
  db.all(`SELECT u.id, u.username, u.display_name, u.avatar_color, u.avatar_url
          FROM group_members gm JOIN users u ON gm.user_id = u.id
          WHERE gm.group_id = ?`, [groupId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.delete('/api/groups/:id/members/:userId', authenticateToken, (req, res) => {
  const groupId = req.params.id;
  const userId = req.params.userId;
  db.get(`SELECT owner_id FROM groups WHERE id = ?`, [groupId], (err, group) => {
    if (!group) return res.status(404).json({ error: 'Group not found' });
    if (group.owner_id !== req.user.id && userId != req.user.id) return res.status(403).json({ error: 'Not allowed' });
    db.run(`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`, [groupId, userId], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

app.delete('/api/groups/:id', authenticateToken, (req, res) => {
  const groupId = req.params.id;
  db.get(`SELECT owner_id FROM groups WHERE id = ?`, [groupId], (err, group) => {
    if (!group) return res.status(404).json({ error: 'Group not found' });
    if (group.owner_id !== req.user.id) return res.status(403).json({ error: 'Only owner can delete' });
    db.run(`DELETE FROM groups WHERE id = ?`, [groupId], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

app.get('/api/groups/:id/invite', authenticateToken, (req, res) => {
  const groupId = req.params.id;
  db.get(`SELECT invite_code FROM groups WHERE id = ?`, [groupId], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Group not found' });
    res.json({ invite_code: row.invite_code });
  });
});

app.post('/api/groups/join', authenticateToken, (req, res) => {
  const { inviteCode } = req.body;
  db.get(`SELECT id FROM groups WHERE invite_code = ?`, [inviteCode], (err, group) => {
    if (!group) return res.status(404).json({ error: 'Invalid invite' });
    db.get(`SELECT COUNT(*) as count FROM group_members WHERE group_id = ?`, [group.id], (err2, row) => {
      if (row.count >= MAX_GROUP_MEMBERS) return res.status(400).json({ error: 'Group full' });
      db.run(`INSERT OR IGNORE INTO group_members (user_id, group_id) VALUES (?, ?)`, [req.user.id, group.id], function(err3) {
        if (err3) return res.status(500).json({ error: err3.message });
        if (this.changes === 0) return res.status(400).json({ error: 'Already a member' });
        res.json({ success: true, groupId: group.id });
      });
    });
  });
});

app.get('/api/sessions', authenticateToken, (req, res) => {
  db.all(`SELECT id, user_agent, ip, created_at, last_activity, token = ? as current
          FROM sessions WHERE user_id = ?`, [req.token, req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.delete('/api/sessions/:id', authenticateToken, (req, res) => {
  const sessionId = req.params.id;
  db.get(`SELECT user_id, token FROM sessions WHERE id = ?`, [sessionId], (err, row) => {
    if (!row) return res.status(404).json({ error: 'Session not found' });
    if (row.user_id !== req.user.id) return res.status(403).json({ error: 'Not yours' });
    db.run(`DELETE FROM sessions WHERE id = ?`, [sessionId], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      const targetSocket = onlineUsers.get(row.user_id);
      if (targetSocket && row.token === req.token) {
        // force logout current session? But careful: we may be terminating another session of the same user.
      }
      res.json({ success: true });
    });
  });
});

app.delete('/api/sessions', authenticateToken, (req, res) => {
  db.run(`DELETE FROM sessions WHERE user_id = ? AND token != ?`, [req.user.id, req.token], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('Authentication error'));
    socket.userId = decoded.id;
    socket.username = decoded.username;
    next();
  });
});

io.on('connection', (socket) => {
  onlineUsers.set(socket.userId, socket.id);

  socket.on('join-channel', (channelId) => {
    socket.join(`channel-${channelId}`);
  });
  socket.on('leave-channel', (channelId) => {
    socket.leave(`channel-${channelId}`);
  });

  socket.on('send-message', ({ channelId, content, repliedTo }) => {
    if (!content.trim()) return;
    db.run(`INSERT INTO messages (channel_id, sender_id, content, replied_to) VALUES (?, ?, ?, ?)`,
      [channelId, socket.userId, content, repliedTo || null], function(err) {
        if (err) return;
        db.get(`SELECT u.username, u.display_name, u.avatar_color, u.avatar_url FROM users u WHERE u.id = ?`, [socket.userId], (_, user) => {
          const msg = {
            id: this.lastID,
            channel_id: channelId,
            user_id: socket.userId,
            username: user.username,
            display_name: user.display_name,
            avatar_color: user.avatar_color,
            avatar_url: user.avatar_url,
            content,
            timestamp: new Date().toISOString(),
            replied_to: repliedTo || null
          };
          io.to(`channel-${channelId}`).emit('new-message', msg);
        });
    });
  });

  socket.on('dm-join', (friendId) => {
    const room = [socket.userId, friendId].sort().join('-');
    socket.join(`dm-${room}`);
    socket.currentDmRoom = `dm-${room}`;
  });
  socket.on('dm-leave', () => {
    if (socket.currentDmRoom) {
      socket.leave(socket.currentDmRoom);
      socket.currentDmRoom = null;
    }
  });
  socket.on('dm-message', ({ friendId, content, repliedTo }) => {
    if (!content.trim()) return;
    const room = [socket.userId, friendId].sort().join('-');
    db.run(`INSERT INTO messages (sender_id, content, dm_recipient_id, replied_to) VALUES (?, ?, ?, ?)`,
      [socket.userId, content, friendId, repliedTo || null], function(err) {
        if (err) return;
        db.get(`SELECT username, display_name, avatar_color, avatar_url FROM users WHERE id = ?`, [socket.userId], (_, user) => {
          const msg = {
            id: this.lastID,
            sender_id: socket.userId,
            username: user.username,
            display_name: user.display_name,
            avatar_color: user.avatar_color,
            avatar_url: user.avatar_url,
            content,
            timestamp: new Date().toISOString(),
            dm_recipient_id: friendId,
            replied_to: repliedTo || null
          };
          io.to(`dm-${room}`).emit('dm-message', msg);
        });
    });
  });

  socket.on('group-join', (groupId) => {
    socket.join(`group-${groupId}`);
    socket.currentGroupRoom = `group-${groupId}`;
  });
  socket.on('group-leave', (groupId) => {
    socket.leave(`group-${groupId}`);
    socket.currentGroupRoom = null;
  });
  socket.on('group-message', ({ groupId, content, repliedTo }) => {
    if (!content.trim()) return;
    db.get(`SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?`, [groupId, socket.userId], (err, row) => {
      if (!row) return;
      db.run(`INSERT INTO messages (sender_id, content, group_id, replied_to) VALUES (?, ?, ?, ?)`,
        [socket.userId, content, groupId, repliedTo || null], function(err2) {
          if (err2) return;
          db.get(`SELECT username, display_name, avatar_color, avatar_url FROM users WHERE id = ?`, [socket.userId], (_, user) => {
            const msg = {
              id: this.lastID,
              sender_id: socket.userId,
              username: user.username,
              display_name: user.display_name,
              avatar_color: user.avatar_color,
              avatar_url: user.avatar_url,
              content,
              timestamp: new Date().toISOString(),
              group_id: groupId,
              replied_to: repliedTo || null
            };
            io.to(`group-${groupId}`).emit('group-message', msg);
          });
      });
    });
  });

  socket.on('call-join', (room) => {
    socket.join(`call-${room}`);
    // notify other participants
    socket.to(`call-${room}`).emit('call-join', socket.userId);
  });
  socket.on('call-offer', ({ room, offer, to }) => {
    socket.to(`call-${room}`).emit('call-offer', { from: socket.userId, offer });
  });
  socket.on('call-answer', ({ room, answer, to }) => {
    socket.to(`call-${room}`).emit('call-answer', { from: socket.userId, answer });
  });
  socket.on('call-candidate', ({ room, candidate, to }) => {
    socket.to(`call-${room}`).emit('call-candidate', { from: socket.userId, candidate });
  });
  socket.on('call-leave', (room) => {
    socket.leave(`call-${room}`);
    socket.to(`call-${room}`).emit('call-leave', socket.userId);
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(socket.userId);
  });
});

server.listen(PORT, () => {});