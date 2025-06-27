const express = require("express");
const fs = require("fs");
const path = require("path");
const bodyParser = require("body-parser");
const mongoose = require('mongoose');
const os = require('os');
const { exec } = require('child_process');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const JWT_SECRET = 'supersecretkey';
const SALT_ROUNDS = 12;
const MONGO_URI = 'mongodb+srv://adingreyling:iosGoibeQqwXN4zE@cluster0.lyaxdvw.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

const app = express();
const PORT = 3000;
const USERS_FILE = path.join(__dirname, "users.txt");
const INVITES_FILE = path.join(__dirname, "invites.txt");
let serverStartTime = Date.now();

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.use(helmet());

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // limit each IP to 10 requests per minute
  message: { success: false, message: 'Too many requests, please try again later.' }
});
const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { success: false, message: 'Too many admin requests, please try again later.' }
});

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('MongoDB connected');
  // Drop the uid_1 index if it exists (one-time fix)
  mongoose.connection.db.collection('users').dropIndex('uid_1')
    .then(() => console.log('Dropped uid_1 index'))
    .catch(e => console.log('Index uid_1 not found or already dropped'));

  // One-time fix: Clean up users with invalid bannedUntil values
  mongoose.connection.db.collection('users').updateMany(
    { $or: [ { bannedUntil: "Invalid Date" }, { bannedUntil: "" } ] },
    { $set: { bannedUntil: null } }
  ).then(result => {
    if (result.modifiedCount > 0) {
      console.log(`Fixed ${result.modifiedCount} users with invalid bannedUntil`);
    }
  }).catch(e => {
    console.log('Error fixing bannedUntil:', e.message);
  });
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

const userSchema = new mongoose.Schema({
  userId: { type: Number, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  isAdmin: { type: Boolean, default: false },
  registeredAt: { type: Date, default: Date.now },
  bannedUntil: { type: Date, default: null },
  lastUsernameChange: { type: Date, default: null }
});

const User = mongoose.model('User', userSchema);

const inviteSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true }
});
const Invite = mongoose.model('Invite', inviteSchema);

// --- Purchase Model ---
const purchaseSchema = new mongoose.Schema({
  userId: { type: Number, required: false },
  email: { type: String, required: false },
  product: { type: String, required: true },
  method: { type: String, required: true }, // paypal, btc, bch, doge
  amount: { type: Number, required: true },
  status: { type: String, default: 'pending' }, // pending, paid, delivered
  inviteCode: { type: String },
  createdAt: { type: Date, default: Date.now },
  paymentId: { type: String }, // PayPal order ID or crypto txid
  meta: { type: Object },
});
const Purchase = mongoose.model('Purchase', purchaseSchema);

// --- File Helpers ---
function readLines(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8")
    .split("\n")
    .map(line => line.trim())
    .filter(line => line);
}

function writeLines(file, lines) {
  fs.writeFileSync(file, lines.join("\n") + "\n");
}

function getNextUserID() {
  return readLines(USERS_FILE).length + 1;
}

// --- FIXED: Correctly parse ISO timestamps containing colons
function parseUserLine(line) {
  // Always expect 7 fields, no colons in date fields
  const parts = line.split(":");
  const id = parts[0] || "";
  const username = parts[1] || "";
  const password = parts[2] || "";
  const email = parts[3] || "";
  const role = parts[4] === "admin" ? "admin" : "";
  const registeredAt = parts[5] || "";
  const bannedUntil = parts[6] || "";
  return { id, username, password, email, isAdmin: role === "admin", registeredAt, bannedUntil };
}

function userLineFromObj(user) {
  // id:username:password:email:admin:registeredAt:bannedUntil
  let arr = [user.id, user.username, user.password, user.email, user.isAdmin ? "admin" : "", user.registeredAt || "", user.bannedUntil || ""];
  return arr.join(":");
}

// --- User Management ---
function findUser(username, password) {
  return readLines(USERS_FILE).find(line => {
    const [id, user, pass] = line.split(":");
    return user === username && pass === password;
  });
}

function addUser(id, username, password, email) {
  const users = readLines(USERS_FILE);
  const isFirst = users.length === 0;
  const isAdmin = isFirst;
  // Save registration date as YYYY-MM-DD only
  const now = new Date();
  const date = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,"0")}-${String(now.getDate()).padStart(2,"0")}`;
  const entry = [id, username, password, email, isAdmin ? "admin" : "", date, ""].join(":");
  users.push(entry);
  writeLines(USERS_FILE, users);
}

function updateUsers(lines) {
  writeLines(USERS_FILE, lines);
}

function isInviteValid(code) {
  return readLines(INVITES_FILE).includes(code);
}

function consumeInvite(code) {
  const codes = readLines(INVITES_FILE).filter(c => c !== code);
  writeLines(INVITES_FILE, codes);
}

// --- Helper: Generate Invite Code ---
function generateInviteCode() {
  return [...Array(30)].map(() => Math.random().toString(36)[2]).join("");
}

// --- Register ---
app.post("/api/register", authLimiter, async (req, res) => {
  const { username, password, email, invite } = req.body;
  const inviteDoc = await Invite.findOne({ code: invite });
  if (!inviteDoc) return res.json({ success: false, message: "Invalid invite code" });
  const existing = await User.findOne({ username });
  if (existing) return res.json({ success: false, message: "User exists" });
  const isFirst = (await User.countDocuments({})) === 0;
  // Find the highest userId and increment
  const lastUser = await User.findOne().sort({ userId: -1 });
  const userId = lastUser ? lastUser.userId + 1 : 1;
  // Hash password
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const user = new User({ userId, username, password: hash, email, isAdmin: isFirst });
  await user.save();
  await Invite.deleteOne({ code: invite });
  res.json({ success: true });
});

// --- Login ---
app.post("/api/login", authLimiter, async (req, res) => {
  const { username, password, remember } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.json({ success: false, message: "Invalid login" });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ success: false, message: "Invalid login" });
  if (user.bannedUntil && user.bannedUntil > new Date()) {
    const daysLeft = Math.ceil((user.bannedUntil - new Date()) / (1000 * 60 * 60 * 24));
    return res.json({ success: false, message: `Banned for ${daysLeft} more day(s)` });
  }
  // Issue JWT
  const token = jwt.sign({ userId: user.userId, isAdmin: user.isAdmin }, JWT_SECRET, {
    expiresIn: remember ? '30d' : '1h'
  });
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: false, // set to true if using HTTPS
    maxAge: remember ? 30*24*60*60*1000 : undefined // 30 days or session
  });
  res.json({ success: true, isAdmin: user.isAdmin });
});

// --- Logout ---
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// --- Admin API: Get all invites ---
app.get("/api/invites", async (req, res) => {
  const invites = await Invite.find({}, { _id: 0, code: 1 });
  res.json({ invites: invites.map(i => i.code) });
});

// --- Admin API: Generate new invite code ---
app.post("/api/admin/invite", async (req, res) => {
  const newCode = Math.random().toString(36).slice(2) + Date.now().toString(36);
  await new Invite({ code: newCode }).save();
  res.json({ success: true, code: newCode });
});

// --- Admin API: List all users ---
app.get("/api/users", (req, res) => {
  const users = readLines(USERS_FILE).map(parseUserLine);
  res.json({ users });
});

// --- Admin API: Reset password ---
app.post("/api/users/update", (req, res) => {
  const { id, password } = req.body;
  const lines = readLines(USERS_FILE).map(line => {
    const parts = line.split(":");
    if (parts[0] === id.toString()) parts[2] = password;
    return parts.join(":");
  });
  updateUsers(lines);
  res.json({ success: true });
});

// --- Admin API: Ban user ---
app.post("/api/users/delete", (req, res) => {
  const { id } = req.body;
  const lines = readLines(USERS_FILE).filter(line => line.split(":")[0] !== id.toString());
  updateUsers(lines);
  res.json({ success: true });
});

// --- Admin Dashboard: Preload user + invite data ---
app.get("/api/admin/data", async (req, res) => {
  const invites = await Invite.find({}, { _id: 0, code: 1 });
  const users = await User.find({}, { password: 0, __v: 0 });
  res.json({ invites: invites.map(i => i.code), users });
});

// --- Admin Dashboard: Reset password ---
app.post("/api/admin/reset", (req, res) => {
  const { id, password } = req.body;
  const updated = readLines(USERS_FILE).map(line => {
    const parts = line.split(":");
    if (parts[0] === id.toString()) parts[2] = password;
    return parts.join(":");
  });
  writeLines(USERS_FILE, updated);
  res.json({ success: true });
});

// --- Admin Dashboard: Ban user for N days ---
app.post("/api/admin/ban", async (req, res) => {
  const { id, days } = req.body;
  const until = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  await User.updateOne({ userId: id }, { $set: { bannedUntil: until } });
  res.json({ success: true, bannedUntil: until });
});

// --- Admin Dashboard: Unban user ---
app.post("/api/admin/unban", async (req, res) => {
  const { id } = req.body;
  await User.updateOne({ userId: id }, { $set: { bannedUntil: null } });
  res.json({ success: true });
});

// --- Admin Dashboard: Promote user to admin ---
app.post("/api/admin/promote", async (req, res) => {
  const { id } = req.body;
  await User.updateOne({ userId: id }, { $set: { isAdmin: true } });
  res.json({ success: true });
});

// --- Admin Dashboard: Demote admin to regular user ---
app.post("/api/admin/demote", async (req, res) => {
  const { id } = req.body;
  await User.updateOne({ userId: id }, { $set: { isAdmin: false } });
  res.json({ success: true });
});

// --- Admin Dashboard: Delete invite code ---
app.post("/api/admin/delete-invite", async (req, res) => {
  const { code } = req.body;
  await Invite.deleteOne({ code });
  res.json({ success: true });
});

// --- Admin Dashboard: Delete user from database ---
app.post("/api/admin/delete-user", async (req, res) => {
  const { id } = req.body;
  await User.deleteOne({ userId: id });
  res.json({ success: true });
});

// --- Server Status Endpoint ---
app.get('/api/status', async (req, res) => {
  let dbStatus = 'ok';
  let dbPing = null;
  let mongoVersion = 'unknown';
  let dbUptime = null;
  try {
    const start = Date.now();
    await mongoose.connection.db.admin().ping();
    dbPing = Date.now() - start;
    const info = await mongoose.connection.db.admin().serverStatus();
    mongoVersion = info.version;
    dbUptime = info.uptime;
  } catch (e) {
    dbStatus = 'down';
  }

  // Backend uptime
  const backendUptime = Math.floor((Date.now() - serverStartTime) / 1000); // seconds
  // Memory usage
  const mem = process.memoryUsage();
  // CPU load
  const cpuLoad = os.loadavg()[0];
  // Node version
  const nodeVersion = process.version;
  // Disk space (Linux/Unix only, fallback to null)
  let disk = null;
  try {
    exec('df -h /', (err, stdout) => {
      if (!err && stdout) {
        const lines = stdout.split('\n');
        if (lines[1]) {
          const parts = lines[1].split(/\s+/);
          disk = { size: parts[1], used: parts[2], avail: parts[3], use: parts[4] };
        }
      }
      // Dummy email check (simulate OK)
      const email = 'ok';
      res.json({
        backend: 'ok',
        db: dbStatus,
        dbPing,
        backendUptime,
        dbUptime,
        memory: { rss: mem.rss, heapUsed: mem.heapUsed, heapTotal: mem.heapTotal },
        cpuLoad,
        nodeVersion,
        mongoVersion,
        disk,
        email
      });
    });
  } catch (e) {
    // Dummy email check (simulate OK)
    const email = 'ok';
    res.json({
      backend: 'ok',
      db: dbStatus,
      dbPing,
      backendUptime,
      dbUptime,
      memory: { rss: mem.rss, heapUsed: mem.heapUsed, heapTotal: mem.heapTotal },
      cpuLoad,
      nodeVersion,
      mongoVersion,
      disk: null,
      email
    });
  }
});

// --- JWT Middleware Example (for protected routes) ---
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    User.findOne({ userId: payload.userId }).then(user => {
      if (!user) {
        return res.status(401).json({ error: 'User not found' });
      }
      req.user = payload;
      next();
    });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Apply admin rate limiter to all /api/admin routes
app.use('/api/admin', adminLimiter);

// --- Profile Info Endpoint ---
app.get('/api/profile', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ userId: payload.userId });
    if (!user) return res.status(401).json({ error: 'User not found' });
    res.json({ username: user.username, email: user.email, registeredAt: user.registeredAt, isAdmin: user.isAdmin, userId: user.userId });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// --- Profile Update Endpoint ---
app.post('/api/profile', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ success: false, message: 'Not authenticated' });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ userId: payload.userId });
    if (!user) return res.status(401).json({ success: false, message: 'User not found' });
    const { username, password, currentPassword } = req.body;
    if (!username) return res.json({ success: false, message: 'Username cannot be empty.' });
    // Check for username conflict and cooldown
    if (username !== user.username) {
      // Enforce 24-hour cooldown
      if (user.lastUsernameChange && (Date.now() - new Date(user.lastUsernameChange).getTime()) < 24*60*60*1000) {
        return res.json({ success: false, message: 'You can only change your username once every 24 hours.' });
      }
      const exists = await User.findOne({ username: { $regex: `^${username}$`, $options: 'i' } });
      if (exists) return res.json({ success: false, message: 'Username already taken.' });
      user.username = username;
      user.lastUsernameChange = new Date();
    }
    if (password) {
      if (!currentPassword) return res.json({ success: false, message: 'Current password required.' });
      const match = await bcrypt.compare(currentPassword, user.password);
      if (!match) return res.json({ success: false, message: 'Current password is incorrect.' });
      const hash = await bcrypt.hash(password, SALT_ROUNDS);
      user.password = hash;
    }
    await user.save();
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ success: false, message: 'Error updating profile.' });
  }
});

// --- PayPal Payment Confirmation & Invite Delivery ---
const fetch = require('node-fetch');
app.post('/api/paypal/confirm', async (req, res) => {
  const { orderID, email } = req.body;
  // TODO: Use your real PayPal credentials
  const PAYPAL_CLIENT = 'AacgR__n50novOL4xFR6cOPgj__FAP3q2Mz7s2JO9rRobqE3AfwwvuFmane7v0weJBHek0oSMssoU8jF';
  const PAYPAL_SECRET = 'EEW_7EK7HUlIcfQ1sIFMEC7yTQ0aQTlI4dhQOlGMJkZBMK1OpZzqeGSdoKeTq76jl7yXo823hzxUHOlI';
  const base = 'https://api-m.sandbox.paypal.com';
  // Get access token
  const basicAuth = Buffer.from(`${PAYPAL_CLIENT}:${PAYPAL_SECRET}`).toString('base64');
  const tokenRes = await fetch(`${base}/v1/oauth2/token`, {
    method: 'POST',
    headers: { 'Authorization': `Basic ${basicAuth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials'
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) return res.json({ success: false, message: 'PayPal auth failed' });
  // Get order details
  const orderRes = await fetch(`${base}/v2/checkout/orders/${orderID}`, {
    headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
  });
  const order = await orderRes.json();
  if (order.status !== 'COMPLETED') return res.json({ success: false, message: 'Order not completed' });
  // Log purchase
  const inviteCode = generateInviteCode();
  await new Purchase({
    email,
    product: 'invite',
    method: 'paypal',
    amount: 1.99,
    status: 'delivered',
    inviteCode,
    paymentId: orderID,
    meta: order
  }).save();
  // Save invite code to DB
  await new Invite({ code: inviteCode }).save();
  res.json({ success: true, inviteCode });
});

// --- Crypto Mark as Paid ---
app.post('/api/crypto/mark-paid', async (req, res) => {
  const { method, email } = req.body;
  // Log purchase as pending
  const purchase = await new Purchase({
    email,
    product: 'invite',
    method,
    amount: 1.99,
    status: 'pending'
  }).save();
  res.json({ success: true, purchaseId: purchase._id });
});

// --- Admin: Confirm Crypto Payment and Deliver Invite ---
app.post('/api/crypto/confirm', async (req, res) => {
  const { purchaseId } = req.body;
  const purchase = await Purchase.findById(purchaseId);
  if (!purchase || purchase.status !== 'pending') return res.json({ success: false, message: 'Invalid purchase' });
  const inviteCode = generateInviteCode();
  purchase.status = 'delivered';
  purchase.inviteCode = inviteCode;
  await purchase.save();
  await new Invite({ code: inviteCode }).save();
  res.json({ success: true, inviteCode });
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
