const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');

// Load environment variables
require('dotenv').config({ path: path.join(__dirname, '.env') });

// Environment variables with fallbacks
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS) || 12;
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Validate required environment variables
if (!MONGO_URI) {
  console.error('ERROR: MONGO_URI environment variable is required');
  console.error('Make sure .env file exists in:', __dirname);
  process.exit(1);
}

if (JWT_SECRET === 'fallback-secret-change-in-production') {
  console.warn('WARNING: Using fallback JWT secret. Please set JWT_SECRET environment variable.');
}

const app = express();
let serverStartTime = Date.now();

// Security middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://www.paypal.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api-m.sandbox.paypal.com", "https://api-m.paypal.com"],
      frameSrc: ["'self'", "https://www.paypal.com"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const url = req.url;
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');
  
  console.log(`[${timestamp}] ${method} ${url} - ${ip} - ${userAgent}`);
  next();
});

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 requests per windowMs
  message: { success: false, message: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // limit each IP to 10 registration attempts per hour
  message: { success: false, message: 'Too many registration attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 admin requests per 15 minutes
  message: { success: false, message: 'Too many admin requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // limit each IP to 200 API requests per 15 minutes
  message: { success: false, message: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// MongoDB Connection
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('MongoDB connected successfully');
})
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// MongoDB Models
const userSchema = new mongoose.Schema({
  userId: { type: Number, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  isAdmin: { type: Boolean, default: false },
  registeredAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: null },
  bannedUntil: { type: Date, default: null },
  activeProduct: { type: String }
});

const User = mongoose.model('User', userSchema);

const inviteSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true }
});
const Invite = mongoose.model('Invite', inviteSchema);

// --- Activity Model ---
const activitySchema = new mongoose.Schema({
  userId: { type: Number, required: true },
  action: { type: String, required: true }, // login, password_change, profile_update, etc.
  description: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  ip: { type: String },
  userAgent: { type: String }
});
const Activity = mongoose.model('Activity', activitySchema);

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

// --- License Key Model ---
const licenseKeySchema = new mongoose.Schema({
  userId: { type: Number, required: true },
  key: { type: String, required: true, unique: true },
  duration: { type: String, enum: ['1d', '1w', '1m', 'invite'], required: true },
  product: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date },
  used: { type: Boolean, default: false },
  hwid: { type: String, default: null }
});
const LicenseKey = mongoose.model('LicenseKey', licenseKeySchema);

// --- Helper: Generate Invite Code ---
function generateInviteCode() {
  return [...Array(30)].map(() => Math.random().toString(36)[2]).join("");
}

// --- Helper: Generate License Key ---
function generateLicenseKey() {
  return [...Array(25)].map(() => Math.random().toString(36)[2]).join('').toUpperCase();
}

// --- Helper: Log User Activity ---
async function logActivity(userId, action, description, req = null) {
  try {
    const activity = new Activity({
      userId,
      action,
      description,
      ip: req ? req.ip : null,
      userAgent: req ? req.get('User-Agent') : null
    });
    await activity.save();
  } catch (error) {
    console.error('Error logging activity:', error);
  }
}

// Input validation middleware
const validateRegistration = (req, res, next) => {
  const { username, password, email, invite } = req.body;
  
  // Username validation
  if (!username || username.length < 3 || username.length > 20) {
    return res.status(400).json({ 
      success: false, 
      message: "Username must be between 3 and 20 characters" 
    });
  }
  
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
    return res.status(400).json({ 
      success: false, 
      message: "Username can only contain letters, numbers, underscores, and hyphens" 
    });
  }
  
  // Password validation with complexity requirements
  if (!password || password.length < 8) {
    return res.status(400).json({ 
      success: false, 
      message: "Password must be at least 8 characters long" 
    });
  }
  
  // Check password complexity
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  if (!hasUpperCase || !hasLowerCase || !hasNumbers) {
    return res.status(400).json({ 
      success: false, 
      message: "Password must contain at least one uppercase letter, one lowercase letter, and one number" 
    });
  }
  
  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email)) {
    return res.status(400).json({ 
      success: false, 
      message: "Please provide a valid email address" 
    });
  }
  
  // Invite code validation
  if (!invite || invite.length < 10) {
    return res.status(400).json({ 
      success: false, 
      message: "Invalid invite code" 
    });
  }
  
  next();
};

const validateLogin = (req, res, next) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ 
      success: false, 
      message: "Username and password are required" 
    });
  }
  
  if (username.length < 3 || username.length > 20) {
    return res.status(400).json({ 
      success: false, 
      message: "Invalid username format" 
    });
  }
  
  next();
};

// --- Register ---
app.post("/api/register", registerLimiter, validateRegistration, async (req, res) => {
  try {
    const { username, password, email, invite } = req.body;
    
    // Check if invite code exists
    const inviteDoc = await Invite.findOne({ code: invite });
    if (!inviteDoc) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid invite code" 
      });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: existingUser.username === username ? "Username already exists" : "Email already registered" 
      });
    }
    
    // Check if this is the first user (make admin)
    const isFirst = (await User.countDocuments({})) === 0;
    
    // Find the highest userId and increment
    const lastUser = await User.findOne().sort({ userId: -1 });
    const userId = lastUser ? lastUser.userId + 1 : 1;
    
    // Hash password
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    
    // Create new user
    const user = new User({ 
      userId, 
      username, 
      password: hash, 
      email, 
      isAdmin: isFirst 
    });
    
    await user.save();
    
    // Consume invite code
    await Invite.deleteOne({ code: invite });
    
    res.status(201).json({ 
      success: true, 
      message: "Registration successful" 
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error during registration" 
    });
  }
});

// --- Login ---
app.post("/api/login", authLimiter, validateLogin, async (req, res) => {
  try {
    const { username, password, remember } = req.body;
    
    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: "Invalid username or password" 
      });
    }
    
    // Verify password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ 
        success: false, 
        message: "Invalid username or password" 
      });
    }
    
    // Check if user is banned
    if (user.bannedUntil && user.bannedUntil > new Date()) {
      const daysLeft = Math.ceil((user.bannedUntil - new Date()) / (1000 * 60 * 60 * 24));
      return res.status(403).json({ 
        success: false, 
        message: `Account suspended for ${daysLeft} more day(s)` 
      });
    }
    
    // Update last login time
    await User.updateOne({ userId: user.userId }, { $set: { lastLogin: new Date() } });
    
    // Log login activity
    await logActivity(user.userId, 'login', 'User logged in successfully', req);
    
    // Issue JWT token
    const token = jwt.sign(
      { 
        userId: user.userId, 
        isAdmin: user.isAdmin,
        username: user.username 
      }, 
      JWT_SECRET, 
      {
        expiresIn: remember ? '30d' : '1h'
      }
    );
    
    // Set secure cookie
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'strict',
      secure: NODE_ENV === 'production', // HTTPS only in production
      maxAge: remember ? 30 * 24 * 60 * 60 * 1000 : undefined // 30 days or session
    });
    
    res.json({ 
      success: true, 
      isAdmin: user.isAdmin,
      message: "Login successful" 
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error during login" 
    });
  }
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

// --- Admin API: Reset password ---
app.post("/api/admin/reset", adminLimiter, requireAdmin, async (req, res) => {
  try {
    const { id, password } = req.body;
    
    if (!password || password.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: "Password must be at least 8 characters long" 
      });
    }
    
    // Hash the password using bcrypt
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    
    // Update user in MongoDB
    const result = await User.updateOne(
      { userId: parseInt(id) }, 
      { $set: { password: hash } }
    );
    
    if (result.matchedCount === 0) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }
    
    res.json({ success: true, message: "Password updated successfully" });
    
  } catch (error) {
    console.error('Admin password reset error:', error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error during password reset" 
    });
  }
});

// --- Admin API: Ban user ---
// REMOVED: Legacy file-based endpoint replaced by /api/admin/delete-user

// --- Admin API: Generate new invite code ---
app.post("/api/admin/invite", adminLimiter, requireAdmin, async (req, res) => {
  const newCode = Math.random().toString(36).slice(2) + Date.now().toString(36);
  await new Invite({ code: newCode }).save();
  res.json({ success: true, code: newCode });
});

// --- Admin Dashboard: Preload user + invite data ---
app.get("/api/admin/data", adminLimiter, requireAdmin, async (req, res) => {
  const invites = await Invite.find({}, { _id: 0, code: 1 });
  const users = await User.find({}, { password: 0, __v: 0 });
  res.json({ invites: invites.map(i => i.code), users });
});

// --- Admin Dashboard: Ban user for N days ---
app.post("/api/admin/ban", adminLimiter, requireAdmin, async (req, res) => {
  const { id, days } = req.body;
  const until = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  await User.updateOne({ userId: id }, { $set: { bannedUntil: until } });
  res.json({ success: true, bannedUntil: until });
});

// --- Admin Dashboard: Unban user ---
app.post("/api/admin/unban", adminLimiter, requireAdmin, async (req, res) => {
  const { id } = req.body;
  await User.updateOne({ userId: id }, { $set: { bannedUntil: null } });
  res.json({ success: true });
});

// --- Admin Dashboard: Promote user to admin ---
app.post("/api/admin/promote", adminLimiter, requireAdmin, async (req, res) => {
  const { id } = req.body;
  await User.updateOne({ userId: id }, { $set: { isAdmin: true } });
  res.json({ success: true });
});

// --- Admin Dashboard: Demote admin to regular user ---
app.post("/api/admin/demote", adminLimiter, requireAdmin, async (req, res) => {
  const { id } = req.body;
  await User.updateOne({ userId: id }, { $set: { isAdmin: false } });
  res.json({ success: true });
});

// --- Admin Dashboard: Delete invite code ---
app.post("/api/admin/delete-invite", adminLimiter, requireAdmin, async (req, res) => {
  const { code } = req.body;
  await Invite.deleteOne({ code });
  res.json({ success: true });
});

// --- Admin Dashboard: Delete user from database ---
app.post("/api/admin/delete-user", adminLimiter, requireAdmin, async (req, res) => {
  const { id } = req.body;
  await User.deleteOne({ userId: id });
  res.json({ success: true });
});

// --- Admin: Reset HWID for a license key ---
app.post('/api/admin/reset-hwid', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const { key } = req.body;
    if (!key) return res.status(400).json({ success: false, message: 'License key is required.' });
    const keyDoc = await LicenseKey.findOne({ key });
    if (!keyDoc) return res.status(404).json({ success: false, message: 'License key not found.' });
    keyDoc.hwid = null;
    await keyDoc.save();
    res.json({ success: true, message: 'HWID reset successfully.' });
  } catch (error) {
    console.error('Admin HWID reset error:', error);
    res.status(500).json({ success: false, message: 'Internal server error during HWID reset.' });
  }
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
  // Node version
  const nodeVersion = process.version;

  res.json({
    backend: 'ok',
    db: dbStatus,
    dbPing,
    backendUptime,
    dbUptime,
    memory: { rss: mem.rss, heapUsed: mem.heapUsed, heapTotal: mem.heapTotal },
    nodeVersion,
    mongoVersion
  });
});

// --- JWT Middleware for protected routes ---
function requireAuth(req, res, next) {
  console.log('DEBUG: requireAuth called, cookies:', req.cookies);
  try {
    const token = req.cookies.token;
    
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        error: 'Authentication required' 
      });
    }
    
    const payload = jwt.verify(token, JWT_SECRET);
    
    // Check if user still exists in database
    User.findOne({ userId: payload.userId }).then(user => {
      if (!user) {
        return res.status(401).json({ 
          success: false, 
          error: 'User not found' 
        });
      }
      
      // Check if user is banned
      if (user.bannedUntil && user.bannedUntil > new Date()) {
        return res.status(403).json({ 
          success: false, 
          error: 'Account suspended' 
        });
      }
      
      req.user = payload;
      req.userData = user;
      next();
    }).catch(error => {
      console.error('Database error in auth middleware:', error);
      return res.status(500).json({ 
        success: false, 
        error: 'Internal server error' 
      });
    });
    
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid token' 
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Token expired' 
      });
    }
    
    console.error('Auth middleware error:', error);
    return res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
}

// --- Admin middleware ---
function requireAdmin(req, res, next) {
  requireAuth(req, res, (err) => {
    if (err) return next(err);
    
    if (!req.user.isAdmin) {
      return res.status(403).json({ 
        success: false, 
        error: 'Admin access required' 
      });
    }
    
    next();
  });
}

// --- Profile Info Endpoint ---
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    // Fetch current user data from database to get lastLogin
    const user = await User.findOne({ userId: req.userData.userId });
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    res.json({ 
      success: true,
      username: user.username, 
      email: user.email, 
      registeredAt: user.registeredAt, 
      lastLogin: user.lastLogin,
      isAdmin: user.isAdmin, 
      userId: user.userId 
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

// --- Profile Update Endpoint ---
app.post('/api/profile', requireAuth, async (req, res) => {
  try {
    const { password, currentPassword } = req.body;
    
    // Validate password change
    if (password) {
      if (password.length < 8) {
        return res.status(400).json({ 
          success: false, 
          message: 'Password must be at least 8 characters long' 
        });
      }
      
      if (!currentPassword) {
        return res.status(400).json({ 
          success: false, 
          message: 'Current password required' 
        });
      }
      
      const match = await bcrypt.compare(currentPassword, req.userData.password);
      if (!match) {
        return res.status(400).json({ 
          success: false, 
          message: 'Current password is incorrect' 
        });
      }
      
      const hash = await bcrypt.hash(password, SALT_ROUNDS);
      req.userData.password = hash;
      
      // Log password change activity
      await logActivity(req.userData.userId, 'password_change', 'Password changed successfully', req);
    }
    
    await req.userData.save();
    
    res.json({ 
      success: true, 
      message: 'Profile updated successfully' 
    });
    
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error during profile update' 
    });
  }
});

// --- PayPal Configuration Endpoint ---
app.get('/api/paypal/config', (req, res) => {
  try {
    const clientId = process.env.PAYPAL_CLIENT_ID;
    
    if (!clientId) {
      return res.status(500).json({ 
        success: false, 
        message: 'PayPal not configured' 
      });
    }
    
    res.json({ 
      success: true, 
      clientId: clientId 
    });
    
  } catch (error) {
    console.error('PayPal config error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// --- PayPal License Key Confirmation & Delivery ---
app.post('/api/paypal/confirm-license', requireAuth, async (req, res) => {
  try {
    const { orderID, email, duration, product } = req.body;
    if (!orderID || !email || !duration) {
      return res.status(400).json({ success: false, message: 'Order ID, email, and duration are required' });
    }
    // Prevent duplicate active licenses for the same product
    const existingActive = await LicenseKey.findOne({
      userId: req.user.userId,
      product: product || 'product1',
      used: true,
      expiresAt: { $gt: new Date() }
    });
    if (existingActive) {
      return res.status(400).json({ success: false, message: 'You already have an active license for this product. Please wait for it to expire before purchasing another.' });
    }
    const clientId = process.env.PAYPAL_CLIENT_ID;
    const PAYPAL_SECRET = process.env.PAYPAL_SECRET;
    if (!clientId || !PAYPAL_SECRET) {
      return res.status(500).json({ success: false, message: 'Payment system not configured' });
    }
    const base = NODE_ENV === 'production' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
    // Get access token
    const basicAuth = Buffer.from(`${clientId}:${PAYPAL_SECRET}`).toString('base64');
    const tokenRes = await fetch(`${base}/v1/oauth2/token`, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${basicAuth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials'
    });
    if (!tokenRes.ok) return res.status(500).json({ success: false, message: 'Payment verification failed' });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.status(500).json({ success: false, message: 'Payment authentication failed' });
    // Get order details
    const orderRes = await fetch(`${base}/v2/checkout/orders/${orderID}`, {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
    });
    if (!orderRes.ok) return res.status(500).json({ success: false, message: 'Order verification failed' });
    const order = await orderRes.json();
    if (order.status !== 'COMPLETED') return res.status(400).json({ success: false, message: 'Order not completed' });
    // Calculate expiration
    let expiresAt = new Date();
    if (duration === '1d') expiresAt.setDate(expiresAt.getDate() + 1);
    else if (duration === '1w') expiresAt.setDate(expiresAt.getDate() + 7);
    else if (duration === '1m') expiresAt.setMonth(expiresAt.getMonth() + 1);
    // Generate and save license key
    const licenseKey = generateLicenseKey();
    await new LicenseKey({
      userId: req.user.userId,
      key: licenseKey,
      duration,
      expiresAt,
      product: product || 'product1'
    }).save();
    // Log purchase
    await new Purchase({
      userId: req.user.userId,
      email,
      product: product || 'product1',
      method: 'paypal',
      amount: parseFloat(order.purchase_units[0].amount.value),
      status: 'delivered',
      paymentId: orderID,
      meta: order
    }).save();
    res.json({ success: true, licenseKey });
  } catch (error) {
    console.error('PayPal license key confirmation error:', error);
    res.status(500).json({ success: false, message: 'Internal server error during payment processing' });
  }
});

// --- Get User License Keys ---
app.get('/api/profile/license-keys', requireAuth, async (req, res) => {
  try {
    const keys = await LicenseKey.find({ userId: req.user.userId }).sort({ createdAt: -1 });
    res.json({ success: true, licenseKeys: keys.map(k => ({ key: k.key, duration: k.duration, createdAt: k.createdAt, expiresAt: k.expiresAt, product: k.product, userId: k.userId })) });
  } catch (error) {
    console.error('Fetch license keys error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch license keys' });
  }
});

// --- User Activities Endpoint ---
app.get('/api/activities', requireAuth, async (req, res) => {
  try {
    const activities = await Activity.find({ userId: req.userData.userId })
      .sort({ timestamp: -1 })
      .limit(20); // Get last 20 activities
    
    res.json({ 
      success: true, 
      activities: activities.map(activity => ({
        action: activity.action,
        description: activity.description,
        timestamp: activity.timestamp,
        ip: activity.ip,
        userAgent: activity.userAgent
      }))
    });
  } catch (error) {
    console.error('Activities fetch error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

// --- Get User Invite Codes ---
app.get('/api/profile/invite-codes', requireAuth, async (req, res) => {
  try {
    // Find all purchases of invite codes for this user
    const purchases = await Purchase.find({
      userId: req.user.userId,
      product: 'invite',
      status: 'delivered',
      inviteCode: { $exists: true, $ne: null }
    });
    // Get all invite codes that are still active (exist in Invite collection)
    const codes = await Invite.find({ code: { $in: purchases.map(p => p.inviteCode) } });
    res.json({ success: true, inviteCodes: codes.map(c => c.code) });
  } catch (error) {
    console.error('Fetch invite codes error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch invite codes' });
  }
});

// --- Activate License Key ---
app.post('/api/activate-license', requireAuth, async (req, res) => {
  try {
    console.log('DEBUG: /api/activate-license handler called');
    const { licenseKey, hwid } = req.body;
    const userId = req.user.userId;
    console.log('DEBUG: Attempting to activate license key:', licenseKey, 'for user:', userId, 'with HWID:', hwid);
    // Find the license key and make sure it's not used
    const keyDoc = await LicenseKey.findOne({ key: licenseKey, used: { $ne: true } });
    console.log('DEBUG: LicenseKey document found:', keyDoc);
    if (!keyDoc) {
      return res.status(400).json({ success: false, message: 'Invalid or already used license key' });
    }
    // HWID binding logic
    if (!hwid) {
      return res.status(400).json({ success: false, message: 'HWID is required for activation.' });
    }
    if (keyDoc.hwid && keyDoc.hwid !== hwid) {
      return res.status(403).json({ success: false, message: 'This license key is already bound to a different device. Please contact support or request an HWID reset.' });
    }
    // Assign the key to the activating user and bind HWID
    keyDoc.userId = userId;
    keyDoc.hwid = hwid;
    // Mark the key as used
    keyDoc.used = true;
    await keyDoc.save();
    // Save the product info to the user
    await User.updateOne({ userId }, { $set: { activeProduct: keyDoc.product } });
    res.json({ success: true, product: keyDoc.product });
  } catch (error) {
    console.error('Activate license error:', error);
    res.status(500).json({ success: false, message: 'Internal server error during license activation' });
  }
});

// --- Get User's Activated Product ---
app.get('/api/user-product', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.user.userId });
    if (user && user.activeProduct) {
      // Find the most recent used license key for this user and product
      const keyDoc = await LicenseKey.findOne({ userId: user.userId, product: user.activeProduct, used: true }, {}, { sort: { expiresAt: -1 } });
      if (keyDoc && keyDoc.expiresAt && keyDoc.expiresAt > new Date()) {
        // License is still valid
        return res.json({ success: true, product: user.activeProduct, expiresAt: keyDoc.expiresAt });
      } else {
        // License expired, clear activeProduct
        await User.updateOne({ userId: user.userId }, { $unset: { activeProduct: "" } });
        return res.json({ success: false });
      }
    } else {
      res.json({ success: false });
    }
  } catch (error) {
    console.error('Get user product error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// --- PayPal Invite Code Confirmation & Delivery ---
app.post('/api/paypal/confirm', async (req, res) => {
  try {
    const { orderID, email } = req.body;
    // Try to get userId if user is logged in
    let userId = undefined;
    if (req.cookies && req.cookies.token) {
      try {
        const payload = jwt.verify(req.cookies.token, JWT_SECRET);
        userId = payload.userId;
      } catch (e) {}
    }
    if (!orderID || !email) {
      return res.status(400).json({ success: false, message: 'Order ID and email are required' });
    }
    const clientId = process.env.PAYPAL_CLIENT_ID;
    const PAYPAL_SECRET = process.env.PAYPAL_SECRET;
    if (!clientId || !PAYPAL_SECRET) {
      return res.status(500).json({ success: false, message: 'Payment system not configured' });
    }
    const base = NODE_ENV === 'production' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
    // Get access token
    const basicAuth = Buffer.from(`${clientId}:${PAYPAL_SECRET}`).toString('base64');
    const tokenRes = await fetch(`${base}/v1/oauth2/token`, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${basicAuth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials'
    });
    if (!tokenRes.ok) return res.status(500).json({ success: false, message: 'Payment verification failed' });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.status(500).json({ success: false, message: 'Payment authentication failed' });
    // Get order details
    const orderRes = await fetch(`${base}/v2/checkout/orders/${orderID}`, {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
    });
    if (!orderRes.ok) return res.status(500).json({ success: false, message: 'Order verification failed' });
    const order = await orderRes.json();
    if (order.status !== 'COMPLETED') return res.status(400).json({ success: false, message: 'Order not completed' });
    // Generate and save invite code
    const inviteCode = generateInviteCode();
    await new Invite({ code: inviteCode }).save();
    // Save purchase record for user (if logged in or by email)
    await new Purchase({
      userId,
      email,
      product: 'invite',
      method: 'paypal',
      amount: parseFloat(order.purchase_units[0].amount.value),
      status: 'delivered',
      inviteCode,
      paymentId: orderID,
      meta: order
    }).save();
    res.json({ success: true, inviteCode });
  } catch (error) {
    console.error('PayPal invite code confirmation error:', error);
    res.status(500).json({ success: false, message: 'Internal server error during invite code delivery' });
  }
});

// --- DEV: Clear all collections except Invite ---
app.post('/api/dev/clear-db', async (req, res) => {
  try {
    await User.deleteMany({});
    await Activity.deleteMany({});
    await Purchase.deleteMany({});
    await LicenseKey.deleteMany({});
    res.json({ success: true, message: 'Database cleared except invites.' });
  } catch (error) {
    console.error('DEV clear-db error:', error);
    res.status(500).json({ success: false, message: 'Error clearing database.' });
  }
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

