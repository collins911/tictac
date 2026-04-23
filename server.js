require('dotenv').config();
const express  = require('express');
const http     = require('http');
const { Server } = require('socket.io');
const { createClient } = require('redis');
const IntaSend = require('intasend-node');
const helmet   = require('helmet');
const rateLimit = require('express-rate-limit');
const path     = require('path');
const crypto   = require('crypto');
const bcrypt   = require('bcryptjs');
const hpp      = require('hpp');
const xss      = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const cookieParser = require('cookie-parser');
const session  = require('express-session');
const RedisStore = require('connect-redis').default;

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { 
    transports: ['websocket', 'polling'],
    cors: {
        origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : "*",
        methods: ["GET", "POST"],
        credentials: true
    },
    pingTimeout: 60000,
    pingInterval: 25000,
    connectTimeout: 45000,
    maxHttpBufferSize: 1e6
});

// ─── REDIS ────────────────────────────────────────────────────────────────
const redis = createClient({ 
    url: process.env.REDIS_URL,
    socket: {
        reconnectStrategy: (retries) => Math.min(retries * 100, 3000),
        connectTimeout: 10000
    }
});
redis.on('error',   e => console.error('Redis error:', e.message));
redis.on('connect', () => console.log('Redis connected'));

// ─── IN-MEMORY STATE ──────────────────────────────────────────────────────
let   waitingSocket = null;
const games         = new Map();
const balances      = new Map();
const privateRooms  = new Map();
const userPins      = new Map();
const userCreatedAt = new Map();
const resetTokens   = new Map();
const failedLogins  = new Map();
const ipRequests    = new Map();
const chipBalances  = new Map();
const chipTransfers = new Map();
const transferHistory = new Map();
const paymentVerifications = new Map();
const processedCodes = new Map();

// ─── SECURITY CONFIG ──────────────────────────────────────────────────────
const ADMIN_SECRET = process.env.ADMIN_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const CHIP_ENCRYPTION_KEY = process.env.CHIP_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const CHIP_HMAC_KEY = process.env.CHIP_HMAC_KEY || crypto.randomBytes(32).toString('hex');
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;
const IP_RATE_LIMIT = 100;

// ─── SECURITY MIDDLEWARE ──────────────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            connectSrc: ["'self'", "wss:", "ws:", "https:"],
            imgSrc: ["'self'", "data:"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        },
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-origin" },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: "deny" },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    ieNoOpen: true,
    noSniff: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xssFilter: true
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(cookieParser());
app.use(xss());
app.use(mongoSanitize());
app.use(hpp()));

// Session middleware with dynamic store
app.use((req, res, next) => {
    const store = redis.isReady ? new RedisStore({ client: redis }) : undefined;
    session({
        store: store,
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: process.env.NODE_ENV === 'production',
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000,
            sameSite: 'strict'
        },
        name: 'tictac_sid'
    })(req, res, next);
});

app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1h',
    etag: true,
    lastModified: true
}));

redis.on('ready', () => {
    console.log('✅ Redis ready - session store available');
});

// ─── IP-BASED RATE LIMITING ───────────────────────────────────────────────
const ipRateLimiter = (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowStart = now - 60000;
    
    let record = ipRequests.get(ip);
    if (!record || record.windowStart < windowStart) {
        record = { count: 0, windowStart: now };
    }
    
    record.count++;
    ipRequests.set(ip, record);
    
    if (record.count > IP_RATE_LIMIT) {
        return res.status(429).json({ error: 'Too many requests. Please slow down.' });
    }
    
    next();
};

app.use(ipRateLimiter);

// ─── RATE LIMITING ────────────────────────────────────────────────────────
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many login attempts. Try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.body?.phone || req.ip
});

const depositLimiter = rateLimit({ 
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'Too many deposit attempts.' },
    standardHeaders: true
});

const withdrawLimiter = rateLimit({ 
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: { error: 'Too many withdrawal attempts.' },
    standardHeaders: true
});

const resetLimiter = rateLimit({ 
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: { error: 'Too many reset attempts.' },
    standardHeaders: true
});

const adminLimiter = rateLimit({ 
    windowMs: 5 * 60 * 1000,
    max: 20,
    message: { error: 'Too many admin requests.' }
});

const transferLimiter = rateLimit({
    windowMs: 60000,
    max: 3,
    message: { error: 'Too many transfers. Slow down.' }
});

// ─── CONSTANTS ────────────────────────────────────────────────────────────
const ENTRY_FEE   = 50;
const WIN_PRIZE   = 85;
const DRAW_REFUND = 50;
const WITHDRAW_FEE = 10;
const DEMO_BONUS  = 1000;
const DEMO_CHIPS  = 1000;
const MAX_BALANCE = 1000000;
const MIN_WITHDRAWAL = 100;
const TRANSFER_FEE_PERCENT = 2;
const MIN_TRANSFER_FEE = 1;
const WIN_COMBOS  = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];

// ─── INTASEND ─────────────────────────────────────────────────────────────
const intasend = new IntaSend(
    process.env.INTASEND_PUBLISHABLE_KEY,
    process.env.INTASEND_SECRET_KEY,
    process.env.NODE_ENV !== 'production'
);

// ─── CHIP ENCRYPTION ──────────────────────────────────────────────────────
const encryptChipBalance = (phone, balance) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(CHIP_ENCRYPTION_KEY, 'hex').slice(0, 32), iv);
    
    const data = JSON.stringify({
        phone,
        balance,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(8).toString('hex')
    });
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
};

const decryptChipBalance = (encryptedData) => {
    try {
        const parts = encryptedData.split(':');
        if (parts.length !== 3) return null;
        
        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const encrypted = parts[2];
        
        const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(CHIP_ENCRYPTION_KEY, 'hex').slice(0, 32), iv);
        decipher.setAuthTag(authTag);
        
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        const data = JSON.parse(decrypted);
        if (Date.now() - data.timestamp > 300000) return null;
        
        return data;
    } catch (e) {
        console.error('Chip decryption failed:', e);
        return null;
    }
};

const signChipTransaction = (data) => {
    const hmac = crypto.createHmac('sha256', CHIP_HMAC_KEY);
    hmac.update(JSON.stringify(data));
    return hmac.digest('hex');
};

const verifyChipTransaction = (data, signature) => {
    const expectedSignature = signChipTransaction(data);
    return crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(signature));
};

// ─── SECURITY HELPERS ─────────────────────────────────────────────────────
const audit = (event, data) => {
    const log = JSON.stringify({ 
        timestamp: new Date().toISOString(), 
        event, 
        ...data,
        ip: data.ip || 'internal'
    });
    console.log(log);
};

const normalizePhone = (phone) => {
    const c = String(phone).replace(/\D/g, '');
    if (/^254\d{9}$/.test(c)) return c;
    if (/^0\d{9}$/.test(c))   return '254' + c.slice(1);
    if (/^\d{9}$/.test(c))    return '254' + c;
    return null;
};

const validateAmount = (amount) => {
    const p = parseInt(amount, 10);
    if (!isFinite(p) || p <= 0 || p > 100000) return null;
    return p;
};

const validatePin = (pin) => {
    return /^\d{4}$/.test(pin);
};

const generateRoomCode = () => {
    return crypto.randomBytes(3).toString('hex').toUpperCase();
};

const generateResetCode = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

const generateSecureToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

const findSocketByPhone = (phone) => {
    for (const [id, sock] of io.sockets.sockets.entries()) {
        if (sock.phone === phone && sock.authenticated) {
            return sock;
        }
    }
    return null;
};

// ─── LOGIN ATTEMPT TRACKING ───────────────────────────────────────────────
const checkLoginAttempts = (phone) => {
    const record = failedLogins.get(phone);
    if (!record) return { allowed: true };
    
    if (record.lockedUntil && record.lockedUntil > Date.now()) {
        const remainingMinutes = Math.ceil((record.lockedUntil - Date.now()) / 60000);
        return { allowed: false, reason: `Account locked. Try again in ${remainingMinutes} minutes.` };
    }
    
    if (record.count >= MAX_LOGIN_ATTEMPTS) {
        record.lockedUntil = Date.now() + LOCKOUT_DURATION;
        failedLogins.set(phone, record);
        return { allowed: false, reason: `Too many failed attempts. Account locked for 15 minutes.` };
    }
    
    return { allowed: true };
};

const recordFailedLogin = (phone) => {
    let record = failedLogins.get(phone) || { count: 0, lockedUntil: null };
    record.count++;
    failedLogins.set(phone, record);
};

const resetLoginAttempts = (phone) => {
    failedLogins.delete(phone);
};

// ─── ADMIN AUTH MIDDLEWARE ────────────────────────────────────────────────
const adminAuth = (req, res, next) => {
    const secret = req.headers['x-admin-secret'] || req.query.secret;
    if (!secret || secret !== ADMIN_SECRET) {
        audit('admin_auth_failed', { ip: req.ip });
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
};

// ─── CHIP MANAGEMENT ──────────────────────────────────────────────────────
const getChipBalance = async (phone) => {
    try {
        if (redis.isReady) {
            const encrypted = await redis.get(`user:${phone}:chips_encrypted`);
            if (encrypted) {
                const data = decryptChipBalance(encrypted);
                if (data && data.phone === phone) {
                    return data.balance;
                }
            }
            return parseInt(await redis.get(`user:${phone}:chips`) || '0');
        }
    } catch(e) {}
    return chipBalances.get(phone) || 0;
};

const setChipBalance = async (phone, balance) => {
    chipBalances.set(phone, balance);
    try {
        if (redis.isReady) {
            const encrypted = encryptChipBalance(phone, balance);
            await redis.set(`user:${phone}:chips_encrypted`, encrypted);
            await redis.set(`user:${phone}:chips`, String(balance));
            await redis.set(`user:${phone}:balance_hash`, 
                crypto.createHash('sha256').update(String(balance)).digest('hex'));
        }
    } catch(e) {}
};

const creditChips = async (phone, amount) => {
    const current = await getChipBalance(phone);
    const newBal = current + amount;
    await setChipBalance(phone, newBal);
    return newBal;
};

const deductChips = async (phone, amount) => {
    const current = await getChipBalance(phone);
    if (current < amount) return false;
    await setChipBalance(phone, current - amount);
    return true;
};

// ─── PIN MANAGEMENT ───────────────────────────────────────────────────────
const hashPin = async (pin) => {
    return await bcrypt.hash(pin, 12);
};

const verifyPin = async (pin, hash) => {
    return await bcrypt.compare(pin, hash);
};

const getUserPin = async (phone) => {
    try {
        if (redis.isReady) {
            const pin = await redis.get(`user:${phone}:pin`);
            if (pin) {
                userPins.set(phone, pin);
                return pin;
            }
        }
    } catch(e) {}
    return userPins.get(phone) || null;
};

const setUserPin = async (phone, pin) => {
    const hashedPin = await hashPin(pin);
    userPins.set(phone, hashedPin);
    try {
        if (redis.isReady) await redis.set(`user:${phone}:pin`, hashedPin);
    } catch(e) {}
};

const userExists = async (phone) => {
    const pin = await getUserPin(phone);
    return !!pin;
};

// ─── USER TIMESTAMP MANAGEMENT ────────────────────────────────────────────
const setUserCreatedAt = async (phone) => {
    const timestamp = Date.now();
    userCreatedAt.set(phone, timestamp);
    try {
        if (redis.isReady) await redis.set(`user:${phone}:created_at`, timestamp);
    } catch(e) {}
};

const getUserCreatedAt = async (phone) => {
    try {
        if (redis.isReady) {
            const ts = await redis.get(`user:${phone}:created_at`);
            return ts ? parseInt(ts) : null;
        }
    } catch(e) {}
    return userCreatedAt.get(phone) || null;
};

// ─── BALANCE MANAGEMENT ───────────────────────────────────────────────────
const getBalance = async (phone) => {
    try {
        if (redis.isReady) {
            const v = await redis.get(`user:${phone}:balance`);
            const bal = parseFloat(v || '0');
            balances.set(phone, bal);
            return Math.min(bal, MAX_BALANCE);
        }
    } catch(e) {}
    return Math.min(balances.get(phone) || 0, MAX_BALANCE);
};

const setBalance = async (phone, amount) => {
    const cappedAmount = Math.min(amount, MAX_BALANCE);
    balances.set(phone, cappedAmount);
    try {
        if (redis.isReady) await redis.set(`user:${phone}:balance`, String(cappedAmount));
    } catch(e) {}
};

const deductBalance = async (phone, amount) => {
    const bal = await getBalance(phone);
    if (bal < amount) return false;
    await setBalance(phone, parseFloat((bal - amount).toFixed(2)));
    return true;
};

const creditBalance = async (phone, amount) => {
    const bal = await getBalance(phone);
    const newBal = Math.min(bal + amount, MAX_BALANCE);
    await setBalance(phone, parseFloat(newBal.toFixed(2)));
    return newBal;
};

const getDemoClaimed = async (phone) => {
    try {
        if (redis.isReady) return await redis.get(`user:${phone}:demo_claimed`);
    } catch(e) {}
    return balances.has(phone) ? '1' : null;
};

const setDemoClaimed = async (phone) => {
    try {
        if (redis.isReady) await redis.set(`user:${phone}:demo_claimed`, '1');
    } catch(e) {}
};

// ─── ONLINE COUNT ─────────────────────────────────────────────────────────
const broadcastOnlineCount = () => {
    const online = io.sockets.sockets.size;
    const searching = waitingSocket ? 1 : 0;
    io.emit('online_count', { online, searching });
};

// ─── PERIODIC CLEANUP ─────────────────────────────────────────────────────
setInterval(() => {
    const now = Date.now();
    
    if (waitingSocket) {
        const stillConnected = io.sockets.sockets.has(waitingSocket.id);
        if (!stillConnected || !waitingSocket.searching) {
            waitingSocket = null;
            broadcastOnlineCount();
        }
    }
    
    for (const [code, room] of privateRooms.entries()) {
        if (now - room.createdAt > 3600000) privateRooms.delete(code);
    }
    
    for (const [key, value] of resetTokens.entries()) {
        if (value.expires < now) resetTokens.delete(key);
    }
    
    for (const [phone, record] of failedLogins.entries()) {
        if (record.lockedUntil && record.lockedUntil < now) failedLogins.delete(phone);
    }
    
    for (const [ip, record] of ipRequests.entries()) {
        if (now - record.windowStart > 60000) ipRequests.delete(ip);
    }
    
    for (const [code, data] of paymentVerifications.entries()) {
        if (now - data.timestamp > 86400000) paymentVerifications.delete(code);
    }
    
    for (const [code, data] of processedCodes.entries()) {
        if (now - data.timestamp > 3600000) processedCodes.delete(code);
    }
}, 30000);

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
    res.json({ status: 'ok', ts: Date.now(), redis: redis.isReady, uptime: process.uptime() });
});

// ─── PUBLIC STATS ─────────────────────────────────────────────────────────
app.get('/api/stats/public', async (req, res) => {
    try {
        let totalUsers = redis.isReady ? (await redis.keys('user:*:pin')).length : userPins.size;
        res.json({ status: 'ok', totalUsers, onlinePlayers: io.sockets.sockets.size, activeGames: games.size });
    } catch (e) { res.status(500).json({ error: 'Internal server error' }); }
});

// ─── ADMIN API ENDPOINTS ──────────────────────────────────────────────────
app.get('/admin/stats', adminLimiter, adminAuth, async (req, res) => {
    try {
        let totalUsers = 0, totalBalance = 0, newUsersToday = 0, newUsersThisWeek = 0;
        const now = Date.now(), oneDayAgo = now - 86400000, oneWeekAgo = now - 604800000;
        
        if (redis.isReady) {
            const pinKeys = await redis.keys('user:*:pin');
            totalUsers = pinKeys.length;
            for (const key of pinKeys) {
                const phone = key.split(':')[1];
                const bal = await getBalance(phone);
                totalBalance += bal;
                const createdAt = await getUserCreatedAt(phone);
                if (createdAt > oneDayAgo) newUsersToday++;
                if (createdAt > oneWeekAgo) newUsersThisWeek++;
            }
        } else {
            totalUsers = userPins.size;
            totalBalance = Array.from(balances.values()).reduce((a, b) => a + b, 0);
            for (const [phone, ts] of userCreatedAt.entries()) {
                if (ts > oneDayAgo) newUsersToday++;
                if (ts > oneWeekAgo) newUsersThisWeek++;
            }
        }
        
        res.json({ totalUsers, totalBalance: totalBalance.toFixed(2), newUsersToday, newUsersThisWeek,
            activeGames: games.size, onlinePlayers: io.sockets.sockets.size, waitingPlayers: waitingSocket ? 1 : 0,
            privateRooms: privateRooms.size, timestamp: new Date().toISOString() });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/count', adminLimiter, adminAuth, async (req, res) => {
    try {
        let totalUsers = redis.isReady ? (await redis.keys('user:*:pin')).length : userPins.size;
        res.json({ totalUsers, timestamp: new Date().toISOString() });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── CHIP PAYMENT ENDPOINTS ───────────────────────────────────────────────
app.post('/api/chips/verify-payment', async (req, res) => {
    const { phone, mpesaCode, chips, amount, bonus } = req.body;
    if (!phone || !mpesaCode || !chips || !amount) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    if (paymentVerifications.has(mpesaCode) && paymentVerifications.get(mpesaCode).verified) {
        return res.status(400).json({ error: 'This transaction code was already used' });
    }
    
    paymentVerifications.set(mpesaCode, { phone, chips, amount, bonus: bonus || 0, timestamp: Date.now(), verified: false });
    
    if (process.env.DEMO_MODE === 'true') {
        const totalChips = chips + (bonus || 0);
        const newBalance = await creditChips(phone, totalChips);
        paymentVerifications.get(mpesaCode).verified = true;
        audit('chips_purchased_demo', { phone, chips: totalChips, amount, mpesaCode });
        return res.json({ msg: 'Chips credited (Demo Mode)', chips: totalChips, newBalance });
    }
    
    audit('chip_purchase_pending', { phone, chips, amount, mpesaCode });
    res.json({ msg: 'Payment submitted for verification. Chips will be credited shortly.', pending: true });
});

app.post('/admin/verify-payment', adminAuth, async (req, res) => {
    const { mpesaCode, approved } = req.body;
    const verification = paymentVerifications.get(mpesaCode);
    if (!verification) return res.status(404).json({ error: 'Verification not found' });
    if (verification.verified) return res.status(400).json({ error: 'Already verified' });
    
    if (approved) {
        const totalChips = verification.chips + (verification.bonus || 0);
        const newBalance = await creditChips(verification.phone, totalChips);
        verification.verified = true;
        audit('chips_purchased', { phone: verification.phone, chips: totalChips, amount: verification.amount, mpesaCode });
        const playerSocket = findSocketByPhone(verification.phone);
        if (playerSocket) playerSocket.emit('chips_credited', { chips: totalChips, newBalance });
        res.json({ msg: 'Chips credited', newBalance });
    } else {
        paymentVerifications.delete(mpesaCode);
        res.json({ msg: 'Payment rejected' });
    }
});

app.get('/admin/pending-payments', adminAuth, (req, res) => {
    const pending = [];
    for (const [code, data] of paymentVerifications.entries()) {
        if (!data.verified) pending.push({ mpesaCode: code, phone: data.phone, chips: data.chips, amount: data.amount, timestamp: new Date(data.timestamp).toISOString() });
    }
    res.json({ pending });
});

// ─── CHIP TRANSFER ENDPOINTS ─────────────────────────────────────────────
app.get('/api/transfers', async (req, res) => {
    const phone = req.query.phone;
    if (!phone) return res.status(400).json({ error: 'Phone required' });
    const history = transferHistory.get(phone) || [];
    res.json({ transfers: history });
});

app.post('/api/mpesa-sms-webhook', async (req, res) => {
    const { sms } = req.body;
    console.log('📱 Received SMS:', sms);
    
    const receivedPattern = /Ksh([\d,]+\.?\d*).*from\s+(\d{12}).*code:\s*([A-Z0-9]+)/i;
    const match = sms?.match(receivedPattern);
    
    if (match) {
        const amount = parseFloat(match[1].replace(/,/g, ''));
        const senderPhone = match[2];
        const transactionCode = match[3].toUpperCase();
        
        if (processedCodes.has(transactionCode)) return res.json({ msg: 'Already processed' });
        processedCodes.set(transactionCode, { timestamp: Date.now(), amount, senderPhone });
        
        const autoChips = Math.floor(amount);
        await creditChips(senderPhone, autoChips);
        audit('mpesa_auto_credit', { phone: senderPhone, chips: autoChips, amount, transactionCode });
        
        return res.json({ msg: 'Auto-credited', chips: autoChips });
    }
    
    res.json({ error: 'Not an M-Pesa payment SMS' });
});

// ─── PIN RESET ENDPOINTS ──────────────────────────────────────────────────
app.post('/api/reset-pin/request', resetLimiter, async (req, res) => {
    const { phone } = req.body;
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) return res.status(400).json({ error: 'Invalid phone number.' });
    
    const exists = await userExists(normalizedPhone);
    if (!exists) return res.status(404).json({ error: 'No account found.' });
    
    const resetCode = generateResetCode();
    const token = generateSecureToken();
    resetTokens.set(token, { phone: normalizedPhone, code: resetCode, expires: Date.now() + 600000, attempts: 0, verified: false, verifyToken: null });
    
    audit('pin_reset_requested', { phone: normalizedPhone, ip: req.ip });
    
    if (process.env.DEMO_MODE === 'true') return res.json({ msg: 'Reset code generated (Demo Mode)', demoCode: resetCode, token });
    res.json({ msg: 'Reset code sent to your phone.', token });
});

app.post('/api/reset-pin/verify', async (req, res) => {
    const { token, code } = req.body;
    if (!token || !code) return res.status(400).json({ error: 'Token and code required.' });
    
    const resetData = resetTokens.get(token);
    if (!resetData) return res.status(400).json({ error: 'Invalid or expired token.' });
    if (resetData.expires < Date.now()) { resetTokens.delete(token); return res.status(400).json({ error: 'Reset code has expired.' }); }
    if (resetData.attempts >= 3) { resetTokens.delete(token); return res.status(400).json({ error: 'Too many failed attempts.' }); }
    if (resetData.code !== code) { resetData.attempts++; return res.status(400).json({ error: 'Invalid reset code.' }); }
    
    const verifyToken = generateSecureToken();
    resetData.verified = true;
    resetData.verifyToken = verifyToken;
    res.json({ msg: 'Code verified.', verifyToken });
});

app.post('/api/reset-pin/set', async (req, res) => {
    const { token, verifyToken, newPin } = req.body;
    if (!token || !verifyToken || !newPin) return res.status(400).json({ error: 'Missing required fields.' });
    if (!validatePin(newPin)) return res.status(400).json({ error: 'PIN must be 4 digits.' });
    
    const resetData = resetTokens.get(token);
    if (!resetData) return res.status(400).json({ error: 'Invalid or expired session.' });
    if (!resetData.verified || resetData.verifyToken !== verifyToken) return res.status(400).json({ error: 'Please verify your code first.' });
    
    await setUserPin(resetData.phone, newPin);
    resetTokens.delete(token);
    resetLoginAttempts(resetData.phone);
    audit('pin_reset_complete', { phone: resetData.phone, ip: req.ip });
    res.json({ msg: 'PIN reset successful.' });
});

// ─── GET ROOM INFO ────────────────────────────────────────────────────────
app.get('/api/room/:code', (req, res) => {
    const { code } = req.params;
    const room = privateRooms.get(code.toUpperCase());
    if (room) res.json({ exists: true, creator: room.creator.slice(0, 6) + '****' + room.creator.slice(-2), playerJoined: !!room.playerSocket });
    else res.json({ exists: false });
});

app.post('/api/check-user', async (req, res) => {
    const { phone } = req.body;
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) return res.status(400).json({ error: 'Invalid phone number.' });
    const exists = await userExists(normalizedPhone);
    res.json({ exists });
});

// ─── DEPOSIT ─────────────────────────────────────────────────────────────
app.post('/mpesa/deposit', depositLimiter, async (req, res) => {
    const { phone, amount } = req.body;
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) return res.status(400).json({ error: 'Invalid phone number.' });
    const parsedAmount = validateAmount(amount);
    if (!parsedAmount) return res.status(400).json({ error: 'Invalid amount.' });
    if (process.env.DEMO_MODE === 'true') return res.status(403).json({ error: 'Deposits disabled in demo mode.' });
    
    try {
        const collection = intasend.collection();
        await collection.mpesaStkPush({
            first_name: 'Player', last_name: '', email: `${normalizedPhone}@tictaccash.app`,
            host: process.env.BASE_URL, amount: parsedAmount, phone_number: normalizedPhone,
            api_ref: `deposit_${normalizedPhone}_${Date.now()}`,
        });
        audit('deposit_initiated', { phone: normalizedPhone, amount: parsedAmount, ip: req.ip });
        res.json({ msg: 'STK Prompt Sent! Check your phone.' });
    } catch (err) { res.status(500).json({ error: 'Deposit failed. Please try again.' }); }
});

// ─── WITHDRAWAL ───────────────────────────────────────────────────────────
app.post('/mpesa/withdraw', withdrawLimiter, async (req, res) => {
    const { phone, amount } = req.body;
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) return res.status(400).json({ error: 'Invalid phone number.' });
    const parsedAmount = validateAmount(amount);
    if (!parsedAmount || parsedAmount < MIN_WITHDRAWAL) return res.status(400).json({ error: `Minimum withdrawal is KES ${MIN_WITHDRAWAL}.` });
    if (process.env.DEMO_MODE === 'true') return res.status(403).json({ error: 'Withdrawals disabled in demo mode.' });
    
    const totalDeduct = parsedAmount + WITHDRAW_FEE;
    const deducted = await deductBalance(normalizedPhone, totalDeduct);
    if (!deducted) return res.status(400).json({ error: `Insufficient balance. Need KES ${totalDeduct}.` });
    
    try {
        const payouts = intasend.payouts();
        await payouts.mpesa({ currency: 'KES', requires_approval: 'NO',
            transactions: [{ name: 'Player', account: normalizedPhone, amount: String(parsedAmount), narrative: 'TicTacCash Withdrawal' }] });
        audit('withdrawal_initiated', { phone: normalizedPhone, amount: parsedAmount, ip: req.ip });
        res.json({ msg: `Withdrawal of KES ${parsedAmount} initiated.` });
    } catch (err) {
        await creditBalance(normalizedPhone, totalDeduct);
        res.status(500).json({ error: 'Withdrawal failed. Balance refunded.' });
    }
});

app.use((err, req, res, next) => { console.error('Server error:', err); res.status(500).json({ error: 'Internal server error' }); });

// ─── WINNER CHECK ─────────────────────────────────────────────────────────
const checkWinner = (board) => {
    for (const [a, b, c] of WIN_COMBOS) {
        if (board[a] && board[a] === board[b] && board[a] === board[c]) return board[a];
    }
    return board.every(Boolean) ? 'DRAW' : null;
};

// ─── SOCKET.IO SECURITY ───────────────────────────────────────────────────
io.use((socket, next) => {
    const ip = socket.handshake.address;
    const connections = Array.from(io.sockets.sockets.values()).filter(s => s.handshake.address === ip).length;
    if (connections > 5) return next(new Error('Too many connections from this IP'));
    next();
});

// ─── SOCKET EVENTS ────────────────────────────────────────────────────────
io.on('connection', (socket) => {
    socket.searching = false;
    socket.currentRoom = null;
    socket.authenticated = false;
    socket.ip = socket.handshake.address;
    console.log(`🔌 New connection: ${socket.id} from ${socket.ip}`);
    broadcastOnlineCount();

    socket.on('check_user', async ({ phone }) => {
        const normalizedPhone = normalizePhone(phone);
        if (!normalizedPhone) return socket.emit('error_msg', 'Invalid phone number.');
        const exists = await userExists(normalizedPhone);
        socket.emit('user_check_result', { exists, phone: normalizedPhone });
    });

    socket.on('register', async ({ phone, pin }) => {
        const normalizedPhone = normalizePhone(phone);
        if (!normalizedPhone) return socket.emit('error_msg', 'Invalid phone number.');
        if (!validatePin(pin)) return socket.emit('error_msg', 'PIN must be 4 digits.');
        if (await userExists(normalizedPhone)) {
            audit('register_attempt_existing', { phone: normalizedPhone, ip: socket.ip });
            return socket.emit('error_msg', 'User already exists.');
        }
        const weakPins = ['0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999', '1234'];
        if (weakPins.includes(pin)) return socket.emit('error_msg', 'Please choose a more secure PIN.');
        
        await setUserPin(normalizedPhone, pin);
        await setUserCreatedAt(normalizedPhone);
        await creditChips(normalizedPhone, DEMO_CHIPS);
        await setDemoClaimed(normalizedPhone);
        audit('user_registered', { phone: normalizedPhone, ip: socket.ip });
        socket.emit('registration_success', { phone: normalizedPhone });
        console.log(`✅ New user registered: ${normalizedPhone}`);
    });

    socket.on('auth', async ({ phone, pin }) => {
        const normalizedPhone = normalizePhone(phone);
        if (!normalizedPhone) return socket.emit('error_msg', 'Invalid phone number.');
        if (!validatePin(pin)) return socket.emit('error_msg', 'PIN must be 4 digits.');
        
        const attemptCheck = checkLoginAttempts(normalizedPhone);
        if (!attemptCheck.allowed) {
            audit('auth_blocked', { phone: normalizedPhone, reason: attemptCheck.reason, ip: socket.ip });
            return socket.emit('error_msg', attemptCheck.reason);
        }
        
        const storedPin = await getUserPin(normalizedPhone);
        if (!storedPin) return socket.emit('error_msg', 'User not found.');
        
        const pinValid = await verifyPin(pin, storedPin);
        if (!pinValid) {
            recordFailedLogin(normalizedPhone);
            audit('auth_failed', { phone: normalizedPhone, ip: socket.ip });
            return socket.emit('error_msg', 'Invalid PIN.');
        }
        
        resetLoginAttempts(normalizedPhone);
        socket.phone = normalizedPhone;
        socket.authenticated = true;
        socket.join(`phone:${normalizedPhone}`);
        
        const chips = await getChipBalance(normalizedPhone);
        if (chips < ENTRY_FEE) {
            await creditChips(normalizedPhone, DEMO_CHIPS);
            socket.emit('demo_bonus', { chips: DEMO_CHIPS });
        }
        
        const updatedChips = await getChipBalance(normalizedPhone);
        audit('auth_success', { phone: normalizedPhone, ip: socket.ip });
        socket.emit('auth_success', { chips: updatedChips });
        broadcastOnlineCount();
        console.log(`✅ Auth success: ${normalizedPhone} - Chips: ${updatedChips}`);
    });

    // ─── CHIP TRANSFER ────────────────────────────────────────────────────
    socket.on('transfer_chips', async ({ recipientPhone, amount, pin }) => {
        if (!socket.authenticated || !socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        
        const storedPin = await getUserPin(socket.phone);
        const pinValid = await verifyPin(pin, storedPin);
        if (!pinValid) return socket.emit('error_msg', 'Invalid PIN.');
        
        if (amount < 10) return socket.emit('error_msg', 'Minimum transfer is 10 chips.');
        if (amount > 10000) return socket.emit('error_msg', 'Maximum transfer is 10,000 chips.');
        
        const senderBalance = await getChipBalance(socket.phone);
        const fee = Math.max(Math.floor(amount * TRANSFER_FEE_PERCENT / 100), MIN_TRANSFER_FEE);
        const totalDeduction = amount + fee;
        
        if (senderBalance < totalDeduction) return socket.emit('error_msg', `Insufficient chips. Need ${totalDeduction} (${amount} + ${fee} fee).`);
        
        const normalizedRecipient = normalizePhone(recipientPhone);
        if (!normalizedRecipient) return socket.emit('error_msg', 'Invalid recipient phone.');
        if (normalizedRecipient === socket.phone) return socket.emit('error_msg', 'Cannot transfer to yourself.');
        if (!await userExists(normalizedRecipient)) return socket.emit('error_msg', 'Recipient is not registered.');
        
        const transferId = crypto.randomBytes(16).toString('hex');
        
        // Detect suspicious activity
        const recentTransfers = (transferHistory.get(socket.phone) || []).filter(t => t.timestamp > Date.now() - 3600000);
        if (recentTransfers.length > 5) {
            audit('suspicious_rapid_transfers', { from: socket.phone, to: normalizedRecipient, count: recentTransfers.length });
        }
        
        const deducted = await deductChips(socket.phone, totalDeduction);
        if (!deducted) return socket.emit('error_msg', 'Transfer failed. Try again.');
        
        await creditChips(normalizedRecipient, amount);
        
        // Store history
        const transfer = { id: transferId, type: 'sent', counterparty: normalizedRecipient, amount, fee, timestamp: Date.now(), status: 'completed' };
        const receivedTransfer = { id: transferId, type: 'received', counterparty: socket.phone, amount, timestamp: Date.now(), status: 'completed' };
        
        let senderHistory = transferHistory.get(socket.phone) || [];
        senderHistory.unshift(transfer);
        if (senderHistory.length > 50) senderHistory = senderHistory.slice(0, 50);
        transferHistory.set(socket.phone, senderHistory);
        
        let recipientHistory = transferHistory.get(normalizedRecipient) || [];
        recipientHistory.unshift(receivedTransfer);
        if (recipientHistory.length > 50) recipientHistory = recipientHistory.slice(0, 50);
        transferHistory.set(normalizedRecipient, recipientHistory);
        
        const recipientSocket = findSocketByPhone(normalizedRecipient);
        if (recipientSocket) {
            recipientSocket.emit('chips_received', { from: socket.phone, amount, transferId });
        }
        
        socket.emit('transfer_complete', { to: normalizedRecipient, amount, fee, transferId, newBalance: await getChipBalance(socket.phone) });
        audit('chip_transfer', { from: socket.phone, to: normalizedRecipient, amount, fee, transferId });
    });

    socket.on('change_pin', async ({ oldPin, newPin }) => {
        if (!socket.authenticated || !socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (!validatePin(oldPin) || !validatePin(newPin)) return socket.emit('error_msg', 'PIN must be 4 digits.');
        const storedPin = await getUserPin(socket.phone);
        if (!await verifyPin(oldPin, storedPin)) return socket.emit('error_msg', 'Current PIN is incorrect.');
        await setUserPin(socket.phone, newPin);
        audit('pin_changed', { phone: socket.phone, ip: socket.ip });
        socket.emit('pin_changed', {});
    });

    socket.on('create_private_room', async () => {
        if (!socket.authenticated || !socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (socket.searching) return socket.emit('error_msg', 'Already searching.');
        if (socket.currentRoom) return socket.emit('error_msg', 'Already in a room.');
        
        const deducted = await deductChips(socket.phone, ENTRY_FEE);
        if (!deducted) return socket.emit('error_msg', `Insufficient chips. Need ${ENTRY_FEE}.`);
        
        const newBal = await getChipBalance(socket.phone);
        socket.emit('balance_update', { chips: newBal });
        
        const roomCode = generateRoomCode();
        privateRooms.set(roomCode, { code: roomCode, creator: socket.phone, creatorSocket: socket.id, playerSocket: null, playerPhone: null, createdAt: Date.now(), gameStarted: false });
        socket.currentRoom = roomCode;
        socket.join(`room:${roomCode}`);
        
        console.log(`🏠 Private room created: ${roomCode}`);
        socket.emit('room_created', { roomCode, chips: newBal });
        socket.emit('waiting_for_opponent', { roomCode });
    });

    socket.on('join_private_room', async ({ roomCode }) => {
        if (!socket.authenticated || !socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (socket.searching) return socket.emit('error_msg', 'Already searching.');
        if (socket.currentRoom) return socket.emit('error_msg', 'Already in a room.');
        
        const code = roomCode.toUpperCase();
        const room = privateRooms.get(code);
        if (!room) return socket.emit('room_error', { error: 'Room not found.' });
        if (room.gameStarted) return socket.emit('room_error', { error: 'Game in progress.' });
        if (room.playerSocket) return socket.emit('room_error', { error: 'Room is full.' });
        if (room.creator === socket.phone) return socket.emit('room_error', { error: 'Cannot join own room.' });
        
        const deducted = await deductChips(socket.phone, ENTRY_FEE);
        if (!deducted) return socket.emit('error_msg', `Insufficient chips. Need ${ENTRY_FEE}.`);
        
        const newBal = await getChipBalance(socket.phone);
        socket.emit('balance_update', { chips: newBal });
        
        room.playerSocket = socket.id;
        room.playerPhone = socket.phone;
        room.gameStarted = true;
        socket.currentRoom = code;
        socket.join(`room:${code}`);
        
        const creatorSocket = io.sockets.sockets.get(room.creatorSocket);
        const gameId = `private_${code}_${Date.now()}`;
        games.set(gameId, { board: Array(9).fill(null), players: { X: room.creator, O: socket.phone }, sockets: { X: room.creatorSocket, O: socket.id }, currentTurn: 'X', isPrivate: true, roomCode: code });
        
        socket.emit('private_match_found', { gameId, mySymbol: 'O', opponent: room.creator });
        if (creatorSocket) creatorSocket.emit('private_match_found', { gameId, mySymbol: 'X', opponent: socket.phone });
        audit('private_game_started', { roomCode: code });
    });

    socket.on('cancel_private_room', async () => {
        if (!socket.authenticated) return;
        const roomCode = socket.currentRoom;
        if (!roomCode) return;
        const room = privateRooms.get(roomCode);
        if (room && room.creatorSocket === socket.id && !room.gameStarted) {
            privateRooms.delete(roomCode);
            socket.currentRoom = null;
            socket.leave(`room:${roomCode}`);
            await creditChips(socket.phone, ENTRY_FEE);
            const bal = await getChipBalance(socket.phone);
            socket.emit('balance_update', { chips: bal });
            socket.emit('room_cancelled', {});
        }
    });

    socket.on('find_match', async () => {
        if (!socket.authenticated || !socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (socket.searching) return socket.emit('error_msg', 'Already searching.');
        if (socket.currentRoom) return socket.emit('error_msg', 'Leave room first.');
        
        socket.searching = true;
        
        const deducted = await deductChips(socket.phone, ENTRY_FEE);
        if (!deducted) { socket.searching = false; return socket.emit('error_msg', 'Insufficient chips.'); }
        
        const newBal = await getChipBalance(socket.phone);
        socket.emit('balance_update', { chips: newBal });
        
        if (waitingSocket && waitingSocket.id !== socket.id && waitingSocket.searching) {
            const opponent = waitingSocket;
            waitingSocket = null;
            opponent.searching = false;
            socket.searching = false;
            
            const gameId = `game_${crypto.randomUUID()}`;
            socket.join(gameId);
            opponent.join(gameId);
            games.set(gameId, { board: Array(9).fill(null), players: { X: socket.phone, O: opponent.phone }, sockets: { X: socket.id, O: opponent.id }, currentTurn: 'X', isPrivate: false });
            
            audit('game_started', { gameId });
            io.to(gameId).emit('match_found', { gameId, playerX: socket.id, playerO: opponent.id });
            broadcastOnlineCount();
        } else {
            waitingSocket = socket;
            socket.emit('waiting', {});
            broadcastOnlineCount();
        }
    });

    socket.on('cancel_search', async () => {
        if (!socket.authenticated || !socket.searching) return;
        if (waitingSocket && waitingSocket.id === socket.id) waitingSocket = null;
        socket.searching = false;
        await creditChips(socket.phone, ENTRY_FEE);
        const bal = await getChipBalance(socket.phone);
        socket.emit('balance_update', { chips: bal });
        socket.emit('search_cancelled', {});
        broadcastOnlineCount();
    });

    socket.on('make_move', ({ gameId, index }) => {
        const game = games.get(gameId);
        if (!game) return socket.emit('error_msg', 'Game not found.');
        
        const mySymbol = game.sockets.X === socket.id ? 'X' : game.sockets.O === socket.id ? 'O' : null;
        if (!mySymbol) return socket.emit('error_msg', 'Not in this game.');
        if (game.currentTurn !== mySymbol) return socket.emit('error_msg', 'Not your turn.');
        if (typeof index !== 'number' || index < 0 || index > 8) return socket.emit('error_msg', 'Invalid move.');
        if (game.board[index]) return socket.emit('error_msg', 'Cell taken.');
        
        game.board[index] = mySymbol;
        game.currentTurn = mySymbol === 'X' ? 'O' : 'X';
        
        io.to(gameId).emit('move_made', { index, symbol: mySymbol, nextTurn: game.currentTurn });
        
        const result = checkWinner(game.board);
        if (result) finishGame(gameId, game, result);
    });

    socket.on('disconnect', async () => {
        if (socket.currentRoom) {
            const room = privateRooms.get(socket.currentRoom);
            if (room && !room.gameStarted) privateRooms.delete(socket.currentRoom);
        }
        if (waitingSocket && waitingSocket.id === socket.id) {
            waitingSocket = null;
            if (socket.phone && socket.searching) await creditChips(socket.phone, ENTRY_FEE);
        }
        socket.searching = false;
        socket.authenticated = false;
        
        for (const [gameId, game] of games.entries()) {
            if (game.sockets.X === socket.id || game.sockets.O === socket.id) {
                const oppSymbol = game.sockets.X === socket.id ? 'O' : 'X';
                const oppPhone = game.players[oppSymbol];
                const oppSocketId = game.sockets[oppSymbol];
                const oppSocket = io.sockets.sockets.get(oppSocketId);
                
                const newBal = await creditChips(oppPhone, WIN_PRIZE);
                if (oppSocket) {
                    oppSocket.searching = false;
                    oppSocket.currentRoom = null;
                    oppSocket.emit('balance_update', { chips: newBal });
                    oppSocket.emit('game_finished', { result: 'FORFEIT', winner: oppSymbol, winnerSocketId: oppSocketId, prize: WIN_PRIZE });
                }
                games.delete(gameId);
                break;
            }
        }
        broadcastOnlineCount();
    });
});

async function finishGame(gameId, game, result) {
    games.delete(gameId);
    if (game.isPrivate && game.roomCode) privateRooms.delete(game.roomCode);
    
    if (result === 'DRAW') {
        await Promise.all([creditChips(game.players.X, DRAW_REFUND), creditChips(game.players.O, DRAW_REFUND)]);
        const [balX, balO] = await Promise.all([getChipBalance(game.players.X), getChipBalance(game.players.O)]);
        const sX = io.sockets.sockets.get(game.sockets.X);
        const sO = io.sockets.sockets.get(game.sockets.O);
        if (sX) sX.emit('balance_update', { chips: balX });
        if (sO) sO.emit('balance_update', { chips: balO });
        io.to(gameId).emit('game_finished', { result: 'DRAW', winner: null, winnerSocketId: null, refund: DRAW_REFUND });
    } else {
        const winnerPhone = game.players[result];
        const winnerSocketId = game.sockets[result];
        const newBal = await creditChips(winnerPhone, WIN_PRIZE);
        const winnerSocket = io.sockets.sockets.get(winnerSocketId);
        if (winnerSocket) winnerSocket.emit('balance_update', { chips: newBal });
        io.to(gameId).emit('game_finished', { result: 'WIN', winner: result, winnerSocketId, prize: WIN_PRIZE });
    }
    broadcastOnlineCount();
}

async function start() {
    try {
        await redis.connect();
        console.log('✅ Redis connected');
    } catch(e) {
        console.warn('⚠️ Redis unavailable — using in-memory storage');
    }
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => console.log(`🚀 TicTac Cash running on port ${PORT}`));
}

start();