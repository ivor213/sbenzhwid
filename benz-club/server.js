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
const tco = require('tco-node-api');
const compression = require('compression');

// Import email service
const emailService = require('./services/emailService');

// Load environment variables
require('dotenv').config({ path: path.join(__dirname, '.env') });

// Environment variables with fallbacks
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS) || 12;
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const TWOCHECKOUT_MERCHANT_CODE = process.env.TWOCHECKOUT_MERCHANT_CODE;
const TWOCHECKOUT_PRIVATE_KEY = process.env.TWOCHECKOUT_PRIVATE_KEY;
const TWOCHECKOUT_PUBLISHABLE_KEY = process.env.TWOCHECKOUT_PUBLISHABLE_KEY;
const TWOCHECKOUT_SECRET_KEY = process.env.TWOCHECKOUT_SECRET_KEY;

// Initialize 2Checkout
if (NODE_ENV === 'development') {
  console.log('2Checkout credentials:', {
    merchantCode: TWOCHECKOUT_MERCHANT_CODE ? 'SET' : 'NOT SET',
    privateKey: TWOCHECKOUT_PRIVATE_KEY ? 'SET' : 'NOT SET',
    publishableKey: TWOCHECKOUT_PUBLISHABLE_KEY ? 'SET' : 'NOT SET',
    secretKey: TWOCHECKOUT_SECRET_KEY ? 'SET' : 'NOT SET',
    environment: NODE_ENV
  });
}

const twocheckoutClient = tco.config({
  privateKey: TWOCHECKOUT_PRIVATE_KEY,
  sellerId: TWOCHECKOUT_MERCHANT_CODE,
  url: process.env.NODE_ENV !== 'production' 
    ? 'https://sandbox.api.2checkout.com/v2/' 
    : 'https://api.2checkout.com/v2/'
});

if (NODE_ENV === 'development') {
  console.log('2Checkout client initialized:', !!twocheckoutClient);
}

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

// Production security middleware
if (NODE_ENV === 'production') {
  // Force HTTPS in production
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
      next();
    }
  });
}

// Security middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Enable compression
app.use(compression());

// Main route - must come before static middleware
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'shop.html'));
});

// Enhanced static file serving with caching for production
const staticOptions = {
  index: false // Disable automatic index.html serving
};

if (NODE_ENV === 'production') {
  staticOptions.maxAge = '1d'; // Cache static files for 1 day
  staticOptions.etag = true;
  staticOptions.lastModified = true;
}

app.use(express.static(path.join(__dirname, "public"), staticOptions));

// Enhanced security headers for production
const helmetConfig = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://secure.2checkout.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.2checkout.com"],
      frameSrc: ["'self'", "https://secure.2checkout.com"],
      objectSrc: ["'none'"]
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
};

// Add upgradeInsecureRequests only in production
if (NODE_ENV === 'production') {
  helmetConfig.contentSecurityPolicy.directives.upgradeInsecureRequests = [];
}

app.use(helmet(helmetConfig));

// Production rate limiting
const productionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

if (NODE_ENV === 'production') {
  app.use('/api/', productionLimiter);
} else {
  // Disable rate limiting for development
  if (NODE_ENV === 'development') {
    console.log('Development mode: Rate limiting disabled for API routes');
  }
}

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const url = req.url;
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');
  
  if (NODE_ENV === 'development') {
    console.log(`[${timestamp}] ${method} ${url} - ${ip} - ${userAgent}`);
  }
  
  next();
});



// Enhanced Rate Limiting for Spam Protection
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Reduced from 20 to 10 login attempts per 15 minutes
  message: { success: false, message: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful logins
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Reduced from 10 to 5 registration attempts per hour
  message: { success: false, message: 'Too many registration attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Additional rate limiters for spam protection
const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per minute
  message: { success: false, message: 'Too many requests, please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Development mode: disable rate limiting for testing
const checkoutLimiter = NODE_ENV === 'development' 
  ? (req, res, next) => next() // No rate limiting in development
  : rateLimit({
      windowMs: 10 * 60 * 1000, // 10 minutes
      max: 50, // limit each IP to 50 checkout attempts per 10 minutes
      message: { success: false, message: 'Too many checkout attempts, please try again later.' },
      standardHeaders: true,
      legacyHeaders: false,
    });

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 50, // limit each IP to 50 API requests per minute
  message: { success: false, message: 'API rate limit exceeded.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const cartLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 20, // limit each IP to 20 cart operations per minute
  message: { success: false, message: 'Too many cart operations. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// IP-based blocking for suspicious activity
const blockedIPs = new Set();
const suspiciousIPs = new Map(); // IP -> { count: number, firstSeen: timestamp }



// Middleware to track suspicious IPs
const trackSuspiciousActivity = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  
  // Check if IP is already blocked
  if (blockedIPs.has(ip)) {
    return res.status(403).json({ 
      success: false, 
      message: 'Access denied due to suspicious activity.' 
    });
  }
  
  // Track suspicious patterns
  const userAgent = req.get('User-Agent') || '';
  const isSuspicious = 
    !userAgent || 
    userAgent.length < 10 || 
    userAgent.includes('bot') || 
    userAgent.includes('crawler') ||
    userAgent.includes('spider') ||
    req.headers['x-forwarded-for']?.includes(',') || // Multiple proxies
    req.headers['x-real-ip'] && req.headers['x-forwarded-for'];
  
  if (isSuspicious) {
    const now = Date.now();
    const suspicious = suspiciousIPs.get(ip) || { count: 0, firstSeen: now };
    suspicious.count++;
    
    // Block IP if too many suspicious requests
    if (suspicious.count > 10) {
      blockedIPs.add(ip);
      console.log(`Blocked suspicious IP: ${ip}`);
      return res.status(403).json({ 
        success: false, 
        message: 'Access denied due to suspicious activity.' 
      });
    }
    
    suspiciousIPs.set(ip, suspicious);
  }
  
  next();
};

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 admin requests per 15 minutes
  message: { success: false, message: 'Too many admin requests, please try again later.' },
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

// Create database indexes for better performance
mongoose.connection.once('open', async () => {
  console.log('Connected to MongoDB');
  
  try {
    // Create indexes for better performance
    await User.collection.createIndex({ email: 1 }, { unique: true });
    await User.collection.createIndex({ userId: 1 });
    await Order.collection.createIndex({ orderId: 1 }, { unique: true });
    await Order.collection.createIndex({ customerEmail: 1 });
    await Order.collection.createIndex({ createdAt: -1 });
    await Activity.collection.createIndex({ userId: 1 });
    await Activity.collection.createIndex({ timestamp: -1 });
    console.log('Database indexes created successfully');
  } catch (error) {
    console.error('Error creating database indexes:', error);
  }
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
  activeProduct: { type: String },
  cart: { type: Array, default: [] },
  resetToken: { type: String, default: null },
  resetTokenExpiry: { type: Date, default: null }
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
  method: { type: String, required: true }, // 2checkout, btc, bch, doge
  amount: { type: Number, required: true },
  status: { type: String, default: 'pending' }, // pending, paid, delivered
  inviteCode: { type: String },
  createdAt: { type: Date, default: Date.now },
  paymentId: { type: String }, // 2Checkout session ID or crypto txid
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

// --- Order Model ---
const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  userId: { type: Number, required: false },
  customerEmail: { type: String, required: true },
  items: [{
    id: String,
    name: String,
    price: Number,
    quantity: Number,
    image: String
  }],
  shipping: {
    firstName: String,
    lastName: String,
    email: String,
    phone: String,
    address: {
      line1: String,
      city: String,
      state: String,
      postal_code: String,
      country: String
    },
    city: String,
    state: String,
    zipCode: String,
    country: String,
    shippingMethod: String
  },
  payment: {
    sessionId: String,
    amount: Number,
    currency: String,
    status: String
  },
  totals: {
    subtotal: Number,
    shipping: Number,
    tax: Number,
    total: Number
  },
  status: { type: String, default: 'pending', enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled'] },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Order = mongoose.model('Order', orderSchema);

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
// Enhanced input validation and sanitization
const sanitizeInput = (str) => {
  if (typeof str !== 'string') return '';
  return str.trim().replace(/[<>]/g, ''); // Remove potential HTML tags
};

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validateRegistration = (req, res, next) => {
  const { username, password, email, invite } = req.body;
  
  // Sanitize inputs
  const sanitizedUsername = sanitizeInput(username);
  const sanitizedEmail = sanitizeInput(email);
  const sanitizedInvite = sanitizeInput(invite);
  
  if (!sanitizedUsername || !password || !sanitizedEmail || !sanitizedInvite) {
    return res.status(400).json({ 
      success: false, 
      message: "All fields are required" 
    });
  }
  
  // Username validation with spam protection
  if (sanitizedUsername.length < 3 || sanitizedUsername.length > 20) {
    return res.status(400).json({ 
      success: false, 
      message: "Username must be between 3 and 20 characters" 
    });
  }
  
  // Check for suspicious username patterns
  const suspiciousPatterns = [
    /admin/i, /root/i, /system/i, /test/i, /spam/i, /bot/i, /crawler/i,
    /[0-9]{6,}/, // Too many consecutive numbers
    /[a-z]{10,}/, // Too many consecutive letters
    /[A-Z]{5,}/, // Too many consecutive uppercase
    /[!@#$%^&*]{3,}/ // Too many consecutive special chars
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(sanitizedUsername)) {
      return res.status(400).json({ 
        success: false, 
        message: "Username contains invalid patterns" 
      });
    }
  }
  
  if (!/^[a-zA-Z0-9_-]+$/.test(sanitizedUsername)) {
    return res.status(400).json({ 
      success: false, 
      message: "Username can only contain letters, numbers, underscores, and hyphens" 
    });
  }
  
  // Password validation with enhanced complexity requirements
  if (!password || password.length < 8) {
    return res.status(400).json({ 
      success: false, 
      message: "Password must be at least 8 characters long" 
    });
  }
  
  if (password.length > 128) {
    return res.status(400).json({ 
      success: false, 
      message: "Password is too long" 
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
  
  // Check for common weak passwords
  const weakPasswords = [
    'password', '123456', 'qwerty', 'admin', 'letmein', 'welcome',
    'monkey', 'dragon', 'master', 'football', 'baseball'
  ];
  
  if (weakPasswords.includes(password.toLowerCase())) {
    return res.status(400).json({ 
      success: false, 
      message: "Password is too common, please choose a stronger password" 
    });
  }
  
  // Email validation with spam protection
  if (!validateEmail(sanitizedEmail)) {
    return res.status(400).json({ 
      success: false, 
      message: "Please provide a valid email address" 
    });
  }
  
  // Check for disposable email domains
  const disposableDomains = [
    '10minutemail.com', 'tempmail.org', 'guerrillamail.com', 'mailinator.com',
    'throwaway.email', 'temp-mail.org', 'sharklasers.com', 'getairmail.com'
  ];
  
  const emailDomain = sanitizedEmail.split('@')[1]?.toLowerCase();
  if (disposableDomains.includes(emailDomain)) {
    return res.status(400).json({ 
      success: false, 
      message: "Disposable email addresses are not allowed" 
    });
  }
  
  // Invite code validation
  if (!sanitizedInvite || sanitizedInvite.length < 10) {
    return res.status(400).json({ 
      success: false, 
      message: "Invalid invite code" 
    });
  }
  

  
  // Store sanitized values for use in the route
  req.body.username = sanitizedUsername;
  req.body.email = sanitizedEmail;
  req.body.invite = sanitizedInvite;
  
  next();
};

// Cleanup function for expired IPs
const cleanupExpiredData = () => {
  const now = Date.now();
  
  // Clean up old suspicious IP entries (older than 1 hour)
  for (const [ip, data] of suspiciousIPs.entries()) {
    if (now - data.firstSeen > 60 * 60 * 1000) {
      suspiciousIPs.delete(ip);
    }
  }
  
  // Unblock IPs after 24 hours
  // Note: This is a simple implementation. In production, you might want to persist blocked IPs
  console.log(`Cleanup: ${suspiciousIPs.size} suspicious IPs tracked`);
};

// Run cleanup every 10 minutes
setInterval(cleanupExpiredData, 10 * 60 * 1000);

// Clean up login activity logs to save database space
const cleanupLoginLogs = async () => {
  try {
    const result = await Activity.deleteMany({ 
      action: 'login',
      description: 'User logged in successfully'
    });
    console.log(`Cleaned up ${result.deletedCount} login activity logs`);
  } catch (error) {
    console.error('Error cleaning up login logs:', error);
  }
};

// Run login log cleanup once on startup
cleanupLoginLogs();

const validateLogin = (req, res, next) => {
  const { username, password } = req.body;
  
  // Sanitize inputs
  const sanitizedUsername = sanitizeInput(username);
  
  if (!sanitizedUsername || !password) {
    return res.status(400).json({ 
      success: false, 
      message: "Username and password are required" 
    });
  }
  
  if (sanitizedUsername.length < 3 || sanitizedUsername.length > 20) {
    return res.status(400).json({ 
      success: false, 
      message: "Invalid username format" 
    });
  }
  
  // Check for suspicious patterns in login attempts
  const suspiciousPatterns = [
    /admin/i, /root/i, /system/i, /test/i, /spam/i, /bot/i, /crawler/i
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(sanitizedUsername)) {
      console.log(`Suspicious login attempt with username: ${sanitizedUsername}`);
    }
  }
  
  // Store sanitized username
  req.body.username = sanitizedUsername;
  
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
    
    // Send welcome email to new user
    try {
      await emailService.sendWelcomeEmail(user);
      console.log('Welcome email sent to:', user.email);
    } catch (emailError) {
      console.error('Failed to send welcome email:', emailError);
    }
    
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

// Apply general spam protection middleware
app.use(trackSuspiciousActivity);
// Only apply general limiter in production
if (NODE_ENV === 'production') {
  app.use(generalLimiter);
} else {
  if (NODE_ENV === 'development') {
    console.log('Development mode: General rate limiting disabled');
  }
}

// --- Logout ---
app.post('/api/logout', apiLimiter, (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});



// --- Auth Status ---
app.get('/api/auth/status', apiLimiter, (req, res) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.json({ authenticated: false });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ 
      authenticated: true, 
      user: {
        userId: decoded.userId,
        username: decoded.username,
        isAdmin: decoded.isAdmin
      }
    });
  } catch (error) {
    res.clearCookie('token');
    res.json({ authenticated: false });
  }
});

// --- Debug: Check Admin Status ---
app.get('/api/debug/admin-status', requireAuth, (req, res) => {
  res.json({
    success: true,
    userData: req.userData,
    user: req.user,
    isAdmin: req.userData?.isAdmin,
    userId: req.userData?.userId
  });
});

// --- Debug: Make User Admin (temporary) ---
app.post('/api/debug/make-admin', requireAuth, async (req, res) => {
  try {
  
    
    await User.updateOne(
      { userId: req.userData.userId }, 
      { $set: { isAdmin: true } }
    );
    
    // Update the current userData
    req.userData.isAdmin = true;
    

    
    res.json({
      success: true,
      message: 'User is now admin',
      userData: req.userData
    });
  } catch (error) {
    console.error('Make admin error:', error);
    res.status(500).json({ success: false, message: 'Failed to make user admin' });
  }
});

// --- Debug: Check Current User ---
app.get('/api/debug/current-user', requireAuth, (req, res) => {
  res.json({
    success: true,
    userData: req.userData,
    user: req.user,
    isAdmin: req.userData?.isAdmin,
    userId: req.userData?.userId
  });
});

// --- Debug: Force Make Admin ---
app.post('/api/debug/force-admin', async (req, res) => {
  try {
    // Get user from token without requiring admin
    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token found' });
    }
    
    const payload = jwt.verify(token, JWT_SECRET);

    
    // Update user to admin
    await User.updateOne(
      { userId: payload.userId }, 
      { $set: { isAdmin: true } }
    );
    

    
    res.json({
      success: true,
      message: 'User is now admin',
      userId: payload.userId
    });
  } catch (error) {
    console.error('Force admin error:', error);
    res.status(500).json({ success: false, message: 'Failed to make user admin' });
  }
});

// --- Debug: Create Admin User ---
app.post('/api/debug/create-admin', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      // Update existing user to admin
      await User.updateOne(
        { username },
        { $set: { isAdmin: true } }
      );

    } else {
      // Create new admin user
      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
      const newAdmin = new User({
        userId: generateInviteCode(),
        username,
        password: hashedPassword,
        isAdmin: true,
        registeredAt: new Date()
      });
      await newAdmin.save();

    }
    
    res.json({
      success: true,
      message: 'Admin user created/updated',
      username
    });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ success: false, message: 'Failed to create admin user' });
  }
});

// --- Debug: Test Admin Access ---
app.get('/api/debug/test-admin', requireAdmin, (req, res) => {
  res.json({
    success: true,
    message: 'Admin access confirmed',
    userData: req.userData
  });
});

// --- Debug: Bypass Admin Check ---
app.get('/api/debug/bypass-admin', requireAuth, (req, res) => {
  res.json({
    success: true,
    message: 'Auth bypass successful',
    userData: req.userData,
    user: req.user
  });
});

// --- Cart API ---
app.get('/api/cart', cartLimiter, requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.user.userId });
    res.json({ 
      success: true, 
      cart: user.cart || [] 
    });
  } catch (error) {
    console.error('Get cart error:', error);
    res.status(500).json({ success: false, message: 'Failed to get cart' });
  }
});

app.post('/api/cart', cartLimiter, requireAuth, async (req, res) => {
  try {
    const { cart } = req.body;
    
    // Validate cart data
    if (!Array.isArray(cart)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid cart data format' 
      });
    }
    
    // Check cart size limits
    if (cart.length > 20) {
      return res.status(400).json({ 
        success: false, 
        message: 'Cart is too large. Maximum 20 items allowed.' 
      });
    }
    
    // Validate each cart item
    for (const item of cart) {
      if (!item.id || !item.name || typeof item.price !== 'number' || typeof item.quantity !== 'number') {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid cart item format' 
        });
      }
      
      // Check quantity limits
      if (item.quantity <= 0 || item.quantity > 10) {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid quantity. Must be between 1 and 10.' 
        });
      }
      
      // Check price limits (prevent negative or extremely high prices)
      if (item.price < 0 || item.price > 10000) {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid price value' 
        });
      }
    }
    await User.updateOne(
      { userId: req.user.userId },
      { $set: { cart: cart || [] } }
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Save cart error:', error);
    res.status(500).json({ success: false, message: 'Failed to save cart' });
  }
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

// --- Login Route ---
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
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

// --- Simple Server Test ---
app.get('/api/test', (req, res) => {
  res.json({ success: true, message: 'Server is running' });
});

// --- Test Order Creation (Alternative) ---
app.get('/api/test-order-get', async (req, res) => {
  try {
  
    res.json({ success: true, message: 'GET test order endpoint works' });
  } catch (error) {
    console.error('Test order GET error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/test-order-create', async (req, res) => {
  try {
  
    
    // Test database connection
    const testOrder = new Order({
      orderId: 'TEST-' + Date.now(),
      customerEmail: 'test@example.com',
      items: [{ id: 'test', name: 'Test Item', price: 10, quantity: 1 }],
      shipping: { email: 'test@example.com' },
      payment: { sessionId: 'test-session', amount: 10, currency: 'usd', status: 'paid' },
      totals: { subtotal: 10, shipping: 0, tax: 0, total: 10 },
      status: 'processing'
    });
    
    await testOrder.save();

    
    res.json({ success: true, message: 'Test order created' });
  } catch (error) {
    console.error('Test order error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Test Orders Count ---
app.get('/api/test-orders', async (req, res) => {
  try {
    const orderCount = await Order.countDocuments();
    const recentOrders = await Order.find().sort({ createdAt: -1 }).limit(5);
    
    res.json({
      success: true,
      orderCount,
      recentOrders: recentOrders.map(order => ({
        orderId: order.orderId,
        customerEmail: order.customerEmail,
        status: order.status,
        total: order.totals?.total,
        createdAt: order.createdAt
      }))
    });
  } catch (error) {
    console.error('Test orders error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Test Database Connection ---
app.get('/api/test-db', async (req, res) => {
  try {

    
    // Test if we can query the database
    const orderCount = await Order.countDocuments();

    
    res.json({ 
      success: true, 
      connectionState: mongoose.connection.readyState,
      orderCount: orderCount
    });
  } catch (error) {
    console.error('Database test error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});



// --- JWT Middleware for protected routes ---
function requireAuth(req, res, next) {

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
    if (err) {

      return next(err);
    }
    

    
    // For debugging, allow access if userData exists (temporary)
    if (!req.userData) {

      return res.status(403).json({ 
        success: false, 
        error: 'Admin access required' 
      });
    }
    
    // Check if user is admin OR if we're in debug mode
    if (!req.userData.isAdmin) {

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
  
    const { licenseKey, hwid } = req.body;
    const userId = req.user.userId;

    // Find the license key and make sure it's not used
    const keyDoc = await LicenseKey.findOne({ key: licenseKey, used: { $ne: true } });

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



// --- 2Checkout Payment Routes ---
app.post('/api/create-payment-intent', async (req, res) => {
  if (NODE_ENV === 'development') {
    console.log('Payment intent request received:', { 
      method: req.method, 
      url: req.url, 
      body: req.body,
      headers: req.headers['content-type']
    });
  }
  
  try {
    const { amount, currency = 'usd', items } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }

    if (NODE_ENV === 'development') {
      console.log('Creating 2Checkout payment session with:', { amount, currency, itemsCount: items?.length });
    }

    // Check if 2Checkout credentials are configured
    if (!TWOCHECKOUT_MERCHANT_CODE || !TWOCHECKOUT_PRIVATE_KEY) {
      console.error('2Checkout credentials not configured');
      return res.status(500).json({ success: false, message: 'Payment system not configured' });
    }

    try {
      // Create payment session with 2Checkout
      const paymentData = {
        Currency: currency.toUpperCase(),
        CustomerIP: req.ip,
        ExternalCustomerReference: `CUST-${Date.now()}`,
        Language: 'en',
        PaymentDetails: {
          Type: 'TEST', // Use 'TEST' for sandbox, 'CC' for production
          Currency: currency.toUpperCase(),
          CustomerIP: req.ip,
          PaymentMethod: {
            Type: 'TEST',
            Currency: currency.toUpperCase(),
            CustomerIP: req.ip
          }
        },
        Items: items.map(item => ({
          Name: item.name,
          Quantity: item.quantity,
          UnitPrice: item.price,
          Tangible: false
        })),
        BillingDetails: {
          Name: 'Customer',
          Email: 'customer@example.com',
          Phone: '1234567890',
          Address: '123 Main St',
          City: 'City',
          State: 'State',
          CountryCode: 'US',
          Zip: '12345'
        }
      };

      if (NODE_ENV === 'development') {
        console.log('2Checkout payment data:', paymentData);
      }
      const paymentSession = await twocheckoutClient.sales.create(paymentData);
      if (NODE_ENV === 'development') {
        console.log('2Checkout payment session created:', paymentSession);
      }

      res.json({
        success: true,
        session_id: paymentSession.SaleId,
        payment_url: `${process.env.WEBSITE_URL || 'http://localhost:3000'}/order-confirmation.html?sessionId=${paymentSession.SaleId}&amount=${amount}`
      });
    } catch (apiError) {
      console.error('2Checkout API error:', apiError);
      
      // Fallback to test mode if API fails
      if (NODE_ENV === 'development') {
        console.log('Falling back to test mode');
      }
      const sessionId = 'TEST-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase();
      
      const paymentSession = {
        SaleId: sessionId,
        PaymentURL: `${process.env.WEBSITE_URL || 'http://localhost:3000'}/order-confirmation.html?sessionId=${sessionId}&amount=${amount}`
      };

      if (NODE_ENV === 'development') {
        console.log('Test payment session created:', paymentSession);
      }

      res.json({
        success: true,
        session_id: paymentSession.SaleId,
        payment_url: `${process.env.WEBSITE_URL || 'http://localhost:3000'}/order-confirmation.html?sessionId=${paymentSession.SaleId}&amount=${amount}`
      });
    }
  } catch (error) {
    console.error('Create payment session error:', error);
    res.status(500).json({ success: false, message: 'Failed to create payment session' });
  }
});



// --- Create Order ---
app.post('/api/create-order', async (req, res) => {
  if (NODE_ENV === 'development') {
    console.log('Create order request received:', { 
      method: req.method, 
      url: req.url, 
      body: req.body 
    });
  }
  
  try {
    const { sessionId, items, shipping, subtotal, shippingCost, tax, total } = req.body;
    
    if (NODE_ENV === 'development') {
      console.log('Order data:', { sessionId, itemsCount: items?.length, shipping, subtotal, shippingCost, tax, total });
      console.log('Shipping data structure:', JSON.stringify(shipping, null, 2));
      console.log('Customer name from shipping:', {
        firstName: shipping?.firstName,
        lastName: shipping?.lastName,
        fullName: shipping?.firstName + ' ' + shipping?.lastName
      });
    }
    
    // Validate required fields
    if (!sessionId || !items || !shipping || !shipping.email) {
      console.error('Missing required fields:', { sessionId: !!sessionId, items: !!items, shipping: !!shipping, email: !!shipping?.email });
      return res.status(400).json({ 
        success: false, 
        message: 'Missing required order information' 
      });
    }
    
    // Get user ID if logged in
    let userId = null;
    if (req.cookies && req.cookies.token) {
      try {
        const payload = jwt.verify(req.cookies.token, JWT_SECRET);
        userId = payload.userId;
      } catch (e) {
        // Token invalid, continue without user ID
      }
    }

    // Generate unique order ID
    const orderId = 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase();
    if (NODE_ENV === 'development') {
      console.log('Generated order ID:', orderId);
    }

    // Create order in database
    if (NODE_ENV === 'development') {
      console.log('Creating order object...');
    }
    const order = new Order({
      orderId,
      userId,
      customerEmail: shipping.email,
      items,
      shipping,
      payment: {
        sessionId,
        amount: total,
        currency: 'usd',
        status: 'paid'
      },
      totals: {
        subtotal,
        shipping: shippingCost,
        tax,
        total
      },
      status: 'processing'
    });
    if (NODE_ENV === 'development') {
      console.log('Order object created successfully');
      console.log('Order object structure:', JSON.stringify(order.toObject(), null, 2));
      console.log('Saving order to database...');
    }
    try {
      await order.save();
      if (NODE_ENV === 'development') {
        console.log('Order saved successfully:', orderId);
      }
    } catch (saveError) {
      console.error('Order save error:', saveError);
      console.error('Save error details:', {
        name: saveError.name,
        message: saveError.message,
        code: saveError.code,
        stack: saveError.stack
      });
      throw saveError;
    }

    // Log activity if user is logged in
    if (userId) {
      try {
        await logActivity(userId, 'order_placed', `Order ${orderId} placed for $${total}`, req);
        if (NODE_ENV === 'development') {
          console.log('Activity logged successfully');
        }
      } catch (activityError) {
        console.error('Failed to log activity:', activityError);
      }
    }

    // Send order confirmation email to customer (optional)
    try {
      if (emailService && emailService.sendOrderConfirmation) {
        await emailService.sendOrderConfirmation(order);
        if (NODE_ENV === 'development') {
          console.log('Order confirmation email sent to:', order.customerEmail);
        }
      } else {
        if (NODE_ENV === 'development') {
          console.log('Email service not available, skipping email');
        }
      }
    } catch (emailError) {
      console.error('Failed to send order confirmation email:', emailError);
      // Don't fail the order for email errors
    }

    // Send admin notification email (optional)
    try {
      if (emailService && emailService.sendAdminOrderNotification) {
        await emailService.sendAdminOrderNotification(order);
        if (NODE_ENV === 'development') {
          console.log('Admin notification email sent');
        }
      } else {
        if (NODE_ENV === 'development') {
          console.log('Email service not available, skipping admin email');
        }
      }
    } catch (emailError) {
      console.error('Failed to send admin notification email:', emailError);
      // Don't fail the order for email errors
    }

    if (NODE_ENV === 'development') {
      console.log('Order creation successful:', { orderId, customerEmail: shipping.email, total });
    }
    
    res.json({
      success: true,
      orderId,
      message: 'Order created successfully'
    });
  } catch (error) {
    console.error('Create order error:', error);
    console.error('Error stack:', error.stack);
    console.error('Error details:', {
      name: error.name,
      message: error.message,
      code: error.code
    });
    res.status(500).json({ 
      success: false, 
      message: 'Failed to create order',
      error: error.message 
    });
  }
});



// --- Get Order Details ---
app.get('/api/order/:orderId', async (req, res) => {
  try {
    const { orderId } = req.params;
  
    
    const order = await Order.findOne({ orderId });
    
    if (!order) {

      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    if (NODE_ENV === 'development') {
      console.log('DEBUG: Order found:', order.orderId);
      console.log('DEBUG: Order shipping data:', JSON.stringify(order.shipping, null, 2));
      console.log('DEBUG: Customer name from stored order:', {
        firstName: order.shipping?.firstName,
        lastName: order.shipping?.lastName,
        email: order.shipping?.email
      });
    }

    // Check if user is authorized to view this order
    let userId = null;
    let isAdmin = false;
    if (req.cookies && req.cookies.token) {
      try {
        const payload = jwt.verify(req.cookies.token, JWT_SECRET);
        userId = payload.userId;
        isAdmin = payload.isAdmin || false;

      } catch (e) {

      }
    }

    // Allow access if user is admin, logged in and owns the order, or if order email matches
    if (isAdmin) {
      // Admin can view any order

      res.json({ success: true, order });
    } else if (userId && order.userId === userId) {
      // User owns the order

      res.json({ success: true, order });
    } else if (!userId && order.customerEmail) {
      // For guest orders, we could implement email verification here

      res.json({ success: true, order });
    } else {

      res.status(403).json({ success: false, message: 'Unauthorized to view this order' });
    }
  } catch (error) {
    console.error('Get order error:', error);
    res.status(500).json({ success: false, message: 'Failed to get order details' });
  }
});

// --- Get User Orders ---
app.get('/api/user/orders', requireAuth, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json({ success: true, orders });
  } catch (error) {
    console.error('Get user orders error:', error);
    res.status(500).json({ success: false, message: 'Failed to get user orders' });
  }
});

// --- Admin: Get All Orders ---
app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  try {
    if (NODE_ENV === 'development') {
      console.log('DEBUG: Admin orders endpoint called');
      console.log('DEBUG: Request userData:', req.userData);
      console.log('DEBUG: Request query:', req.query);
    }
    
    const { page = 1, limit = 20, status } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (status) {
      query.status = status;
    }
    
    if (NODE_ENV === 'development') {
      console.log('DEBUG: MongoDB query:', query);
      console.log('DEBUG: Skip:', skip, 'Limit:', limit);
    }
    
    const orders = await Order.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    if (NODE_ENV === 'development') {
      console.log('DEBUG: Found orders:', orders.length);
    }
    
    const total = await Order.countDocuments(query);
    if (NODE_ENV === 'development') {
      console.log('DEBUG: Total orders in database:', total);
    }
    
    res.json({
      success: true,
      orders,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get admin orders error:', error);
    res.status(500).json({ success: false, message: 'Failed to get orders' });
  }
});

// --- Admin: Update Order Status ---
app.put('/api/admin/order/:orderId/status', requireAdmin, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;
    
    const validStatuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }
    
    const order = await Order.findOneAndUpdate(
      { orderId },
      { status, updatedAt: Date.now() },
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    // Send status update email to customer
    try {
      await emailService.sendOrderStatusUpdate(order, status);
      if (NODE_ENV === 'development') {
        console.log('Order status update email sent to:', order.customerEmail);
      }
    } catch (emailError) {
      console.error('Failed to send order status update email:', emailError);
    }

    // Send specific emails based on status
    if (status === 'shipped') {
      try {
        await emailService.sendOrderShipped(order);
        if (NODE_ENV === 'development') {
          console.log('Order shipped email sent to:', order.customerEmail);
        }
      } catch (emailError) {
        console.error('Failed to send order shipped email:', emailError);
      }
    } else if (status === 'delivered') {
      try {
        await emailService.sendOrderDelivered(order);
        if (NODE_ENV === 'development') {
          console.log('Order delivered email sent to:', order.customerEmail);
        }
      } catch (emailError) {
        console.error('Failed to send order delivered email:', emailError);
      }
    }
    
    res.json({ success: true, order });
  } catch (error) {
    console.error('Update order status error:', error);
    res.status(500).json({ success: false, message: 'Failed to update order status' });
  }
});

// --- Admin: Delete Order ---
app.delete('/api/admin/order/:orderId', requireAdmin, async (req, res) => {
  try {
    const { orderId } = req.params;
    if (NODE_ENV === 'development') {
      console.log('DEBUG: Attempting to delete order:', orderId);
      console.log('DEBUG: Delete endpoint reached - userData:', req.userData);
    }
    
    const order = await Order.findOneAndDelete({ orderId });
    
    if (!order) {

      return res.status(404).json({ success: false, message: 'Order not found' });
    }
    

    
    // Log the deletion activity
    await logActivity(req.userData.userId, 'delete_order', `Deleted order ${orderId}`, req);
    

    res.json({ success: true, message: 'Order deleted successfully' });
  } catch (error) {
    console.error('Delete order error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete order' });
  }
});

// --- DEV: Clear all collections except Invite ---
app.post('/api/dev/clear-db', async (req, res) => {
  try {
    await User.deleteMany({});
    await Activity.deleteMany({});
    await Purchase.deleteMany({});
    await LicenseKey.deleteMany({});
    await Order.deleteMany({});
    res.json({ success: true, message: 'Database cleared except invites.' });
  } catch (error) {
    console.error('DEV clear-db error:', error);
    res.status(500).json({ success: false, message: 'Error clearing database.' });
  }
});

// --- Page Routes ---
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/checkout', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'checkout.html'));
});

app.get('/orders', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'orders.html'));
});

app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/order-confirmation', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'order-confirmation.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

// Terms and Conditions route
app.get('/terms', (req, res) => {

  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});

// --- Password Reset Request ---
app.post('/api/password-reset-request', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Valid email address required' 
      });
    }
    
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal if email exists or not for security
      return res.json({ 
        success: true, 
        message: 'If an account with this email exists, a password reset link has been sent' 
      });
    }
    
    // Generate reset token (valid for 1 hour)
    const resetToken = require('crypto').randomBytes(32).toString('hex');
    const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    
    // Store reset token in user document
    await User.updateOne(
      { userId: user.userId },
      { 
        resetToken,
        resetTokenExpiry: resetExpiry
      }
    );
    
    // Send password reset email
    try {
      await emailService.sendPasswordReset(user, resetToken);
      if (NODE_ENV === 'development') {
        console.log('Password reset email sent to:', user.email);
      }
    } catch (emailError) {
      console.error('Failed to send password reset email:', emailError);
      return res.status(500).json({ 
        success: false, 
        message: 'Failed to send password reset email' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'If an account with this email exists, a password reset link has been sent' 
    });
    
  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error during password reset request' 
    });
  }
});

// --- Test Email Service ---
app.post('/api/test-email', requireAdmin, async (req, res) => {
  try {
    const testEmail = req.body.email || 'test@example.com';
    
    const testResult = await emailService.sendEmail(
      testEmail,
      'Test Email - SBENZ Club',
      '<h1>Test Email</h1><p>This is a test email from your SBENZ Club email system.</p>'
    );
    
    if (testResult.success) {
      res.json({ 
        success: true, 
        message: 'Test email sent successfully!',
        messageId: testResult.messageId 
      });
    } else {
      res.status(500).json({ 
        success: false, 
        message: 'Failed to send test email',
        error: testResult.error 
      });
    }
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Test email failed' 
    });
  }
});

// --- Password Reset Confirm ---
app.post('/api/password-reset-confirm', authLimiter, async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Token and new password required' 
      });
    }
    
    // Find user with valid reset token
    const user = await User.findOne({ 
      resetToken: token,
      resetTokenExpiry: { $gt: new Date() }
    });
    
    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired reset token' 
      });
    }
    
    // Hash new password
    const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    
    // Update password and clear reset token
    await User.updateOne(
      { userId: user.userId },
      { 
        password: hash,
        resetToken: null,
        resetTokenExpiry: null
      }
    );
    
    // Log password reset activity
    await logActivity(user.userId, 'password_reset', 'Password reset completed', req);
    
    res.json({ 
      success: true, 
      message: 'Password reset successful' 
    });
    
  } catch (error) {
    console.error('Password reset confirm error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error during password reset' 
    });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  // Log error details
  const errorDetails = {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  };
  
  console.error('Error details:', errorDetails);
  
  // Send appropriate error response
  res.status(500).json({
    success: false,
    message: NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message
  });
});

// Catch-all route for SPA behavior (must be last)
app.use((req, res, next) => {
  // Only serve shop.html for non-API routes
  if (!req.path.startsWith('/api/')) {
    res.sendFile(path.join(__dirname, 'public', 'shop.html'));
  } else {
    // For API routes that don't exist, return 404 JSON
    res.status(404).json({ success: false, message: 'API endpoint not found' });
  }
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`🔒 Security: ${NODE_ENV === 'production' ? 'Production mode enabled' : 'Development mode'}`);
});

