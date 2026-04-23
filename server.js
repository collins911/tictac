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
    cors: { origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : "*", methods: ["GET", "POST"], credentials: true },
    pingTimeout: 60000, pingInterval: 25000, connectTimeout: 45000, maxHttpBufferSize: 1e6
});

const redis = createClient({ url: process.env.REDIS_URL, socket: { reconnectStrategy: (retries) => Math.min(retries * 100, 3000), connectTimeout: 10000 } });
redis.on('error', e => console.error('Redis error:', e.message));
redis.on('connect', () => console.log('Redis connected'));

let waitingSocket = null;
const games = new Map();
const balances = new Map();
const privateRooms = new Map();
const userPins = new Map();
const userCreatedAt = new Map();
const resetTokens = new Map();
const failedLogins = new Map();
const ipRequests = new Map();
const chipBalances = new Map();
const transferHistory = new Map();
const paymentVerifications = new Map();
const processedCodes = new Map();
const withdrawalRequests = new Map();
let totalChipsInCirculation = 0;
let totalChipsWithdrawn = 0;
let houseChipBalance = 0;

const ADMIN_SECRET = process.env.ADMIN_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const CHIP_ENCRYPTION_KEY = process.env.CHIP_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const CHIP_HMAC_KEY = process.env.CHIP_HMAC_KEY || crypto.randomBytes(32).toString('hex');
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;
const IP_RATE_LIMIT = 100;

app.use(helmet({
    contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"], styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"], fontSrc: ["'self'", "https://fonts.gstatic.com"], connectSrc: ["'self'", "wss:", "ws:", "https:"], imgSrc: ["'self'", "data:"], frameSrc: ["'none'"], objectSrc: ["'none'"] } },
    crossOriginEmbedderPolicy: true, crossOriginOpenerPolicy: { policy: "same-origin" }, crossOriginResourcePolicy: { policy: "same-origin" },
    dnsPrefetchControl: { allow: false }, frameguard: { action: "deny" }, hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    ieNoOpen: true, noSniff: true, referrerPolicy: { policy: "strict-origin-when-cross-origin" }, xssFilter: true
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(cookieParser());
app.use(xss());
app.use(mongoSanitize());
app.use(hpp());

app.use((req, res, next) => {
    const store = redis.isReady ? new RedisStore({ client: redis }) : undefined;
    session({ store, secret: SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, maxAge: 86400000, sameSite: 'strict' }, name: 'tictac_sid' })(req, res, next);
});

app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h', etag: true, lastModified: true }));
redis.on('ready', () => console.log('Redis ready'));

const ipRateLimiter = (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now(), windowStart = now - 60000;
    let record = ipRequests.get(ip);
    if (!record || record.windowStart < windowStart) record = { count: 0, windowStart: now };
    record.count++; ipRequests.set(ip, record);
    if (record.count > IP_RATE_LIMIT) return res.status(429).json({ error: 'Too many requests.' });
    next();
};
app.use(ipRateLimiter);

const authLimiter = rateLimit({ windowMs: 900000, max: 10, message: { error: 'Too many login attempts.' }, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => req.body?.phone || req.ip });
const resetLimiter = rateLimit({ windowMs: 3600000, max: 3, message: { error: 'Too many reset attempts.' }, standardHeaders: true });
const adminLimiter = rateLimit({ windowMs: 300000, max: 20, message: { error: 'Too many admin requests.' } });
const withdrawLimiter = rateLimit({ windowMs: 3600000, max: 3, message: { error: 'Too many withdrawal attempts.' }, standardHeaders: true });

const ENTRY_FEE = 50, WIN_PRIZE = 85, DRAW_REFUND = 50, DEMO_CHIPS = 1000, MAX_BALANCE = 1000000;
const TRANSFER_FEE_PERCENT = 2, MIN_TRANSFER_FEE = 1, MIN_WITHDRAWAL = 100, WITHDRAWAL_FEE = 5;
const WIN_COMBOS = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];

const intasend = new IntaSend(process.env.INTASEND_PUBLISHABLE_KEY, process.env.INTASEND_SECRET_KEY, process.env.NODE_ENV !== 'production');

const audit = (event, data) => console.log(JSON.stringify({ timestamp: new Date().toISOString(), event, ...data }));
const normalizePhone = (phone) => { const c = String(phone).replace(/\D/g, ''); if (/^254\d{9}$/.test(c)) return c; if (/^0\d{9}$/.test(c)) return '254' + c.slice(1); if (/^\d{9}$/.test(c)) return '254' + c; return null; };
const validatePin = (pin) => /^\d{4}$/.test(pin);
const generateRoomCode = () => crypto.randomBytes(3).toString('hex').toUpperCase();
const generateResetCode = () => Math.floor(100000 + Math.random() * 900000).toString();
const generateSecureToken = () => crypto.randomBytes(32).toString('hex');
const findSocketByPhone = (phone) => { for (const [id, sock] of io.sockets.sockets.entries()) { if (sock.phone === phone && sock.authenticated) return sock; } return null; };
const checkLoginAttempts = (phone) => { const r = failedLogins.get(phone); if (!r) return { allowed: true }; if (r.lockedUntil && r.lockedUntil > Date.now()) return { allowed: false, reason: `Account locked. Try again in ${Math.ceil((r.lockedUntil - Date.now()) / 60000)} minutes.` }; if (r.count >= MAX_LOGIN_ATTEMPTS) { r.lockedUntil = Date.now() + LOCKOUT_DURATION; failedLogins.set(phone, r); return { allowed: false, reason: 'Account locked for 15 minutes.' }; } return { allowed: true }; };
const recordFailedLogin = (phone) => { let r = failedLogins.get(phone) || { count: 0, lockedUntil: null }; r.count++; failedLogins.set(phone, r); };
const resetLoginAttempts = (phone) => { failedLogins.delete(phone); };
const adminAuth = (req, res, next) => { const s = req.headers['x-admin-secret'] || req.query.secret; if (!s || s !== ADMIN_SECRET) return res.status(401).json({ error: 'Unauthorized' }); next(); };

const encryptChipBalance = (phone, balance) => { const iv = crypto.randomBytes(16); const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(CHIP_ENCRYPTION_KEY, 'hex').slice(0, 32), iv); const data = JSON.stringify({ phone, balance, timestamp: Date.now() }); let encrypted = cipher.update(data, 'utf8', 'hex'); encrypted += cipher.final('hex'); return iv.toString('hex') + ':' + cipher.getAuthTag().toString('hex') + ':' + encrypted; };
const decryptChipBalance = (enc) => { try { const p = enc.split(':'); if (p.length !== 3) return null; const d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(CHIP_ENCRYPTION_KEY, 'hex').slice(0, 32), Buffer.from(p[0], 'hex')); d.setAuthTag(Buffer.from(p[1], 'hex')); let dec = d.update(p[2], 'hex', 'utf8'); dec += d.final('utf8'); return JSON.parse(dec); } catch(e) { return null; } };

const getChipBalance = async (phone) => { try { if (redis.isReady) { const enc = await redis.get(`user:${phone}:chips`); if (enc) { const data = decryptChipBalance(enc); if (data && data.phone === phone) return data.balance; } } } catch(e) {} return chipBalances.get(phone) || 0; };
const setChipBalance = async (phone, balance) => { chipBalances.set(phone, balance); try { if (redis.isReady) await redis.set(`user:${phone}:chips`, encryptChipBalance(phone, balance)); } catch(e) {} };
const creditChips = async (phone, amount) => { const cur = await getChipBalance(phone); const nb = cur + amount; await setChipBalance(phone, nb); totalChipsInCirculation += amount; return nb; };
const deductChips = async (phone, amount) => { const cur = await getChipBalance(phone); if (cur < amount) return false; await setChipBalance(phone, cur - amount); totalChipsInCirculation -= amount; return true; };
const creditHouseChips = async (amount) => { houseChipBalance += amount; totalChipsInCirculation += amount; };
const burnChips = async (amount) => { totalChipsInCirculation -= amount; totalChipsWithdrawn += amount; };

const hashPin = async (pin) => await bcrypt.hash(pin, 12);
const verifyPin = async (pin, hash) => await bcrypt.compare(pin, hash);
const getUserPin = async (phone) => { try { if (redis.isReady) { const p = await redis.get(`user:${phone}:pin`); if (p) { userPins.set(phone, p); return p; } } } catch(e) {} return userPins.get(phone) || null; };
const setUserPin = async (phone, pin) => { const hp = await hashPin(pin); userPins.set(phone, hp); try { if (redis.isReady) await redis.set(`user:${phone}:pin`, hp); } catch(e) {} };
const userExists = async (phone) => !!(await getUserPin(phone));
const setUserCreatedAt = async (phone) => { const ts = Date.now(); userCreatedAt.set(phone, ts); try { if (redis.isReady) await redis.set(`user:${phone}:created_at`, ts); } catch(e) {} };

const broadcastOnlineCount = () => io.emit('online_count', { online: io.sockets.sockets.size, searching: waitingSocket ? 1 : 0 });
const broadcastChipStats = () => io.emit('chip_stats', { inCirculation: totalChipsInCirculation, withdrawn: totalChipsWithdrawn, houseBalance: houseChipBalance });

const updateCirculationStats = async () => {
    let total = houseChipBalance;
    if (redis.isReady) {
        const keys = await redis.keys('user:*:chips');
        for (const key of keys) {
            const enc = await redis.get(key);
            if (enc) { const data = decryptChipBalance(enc); if (data) total += data.balance; }
        }
    } else {
        for (const bal of chipBalances.values()) total += bal;
    }
    totalChipsInCirculation = total;
    broadcastChipStats();
};

setInterval(() => {
    const now = Date.now();
    if (waitingSocket) { if (!io.sockets.sockets.has(waitingSocket.id) || !waitingSocket.searching) { waitingSocket = null; broadcastOnlineCount(); } }
    for (const [code, room] of privateRooms.entries()) { if (now - room.createdAt > 3600000) privateRooms.delete(code); }
    for (const [key, value] of resetTokens.entries()) { if (value.expires < now) resetTokens.delete(key); }
    for (const [phone, record] of failedLogins.entries()) { if (record.lockedUntil && record.lockedUntil < now) failedLogins.delete(phone); }
    for (const [ip, record] of ipRequests.entries()) { if (now - record.windowStart > 60000) ipRequests.delete(ip); }
    updateCirculationStats();
}, 30000);

app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now(), redis: redis.isReady }));
app.get('/api/stats/public', async (req, res) => res.json({ status: 'ok', totalUsers: redis.isReady ? (await redis.keys('user:*:pin')).length : userPins.size, onlinePlayers: io.sockets.sockets.size, activeGames: games.size, chipsInCirculation: totalChipsInCirculation, chipsWithdrawn: totalChipsWithdrawn }));
app.get('/admin/stats', adminLimiter, adminAuth, async (req, res) => { let totalUsers = redis.isReady ? (await redis.keys('user:*:pin')).length : userPins.size; res.json({ totalUsers, chipsInCirculation: totalChipsInCirculation, chipsWithdrawn: totalChipsWithdrawn, houseBalance: houseChipBalance, activeGames: games.size, onlinePlayers: io.sockets.sockets.size, pendingWithdrawals: withdrawalRequests.size }); });
app.get('/admin/count', adminLimiter, adminAuth, async (req, res) => res.json({ totalUsers: redis.isReady ? (await redis.keys('user:*:pin')).length : userPins.size }));

app.post('/api/chips/verify-payment', async (req, res) => {
    const { phone, mpesaCode, chips, amount, bonus } = req.body;
    if (!phone || !mpesaCode || !chips || !amount) return res.status(400).json({ error: 'Missing fields' });
    if (paymentVerifications.has(mpesaCode) && paymentVerifications.get(mpesaCode).verified) return res.status(400).json({ error: 'Code already used' });
    paymentVerifications.set(mpesaCode, { phone, chips, amount, bonus: bonus || 0, timestamp: Date.now(), verified: false });
    if (process.env.DEMO_MODE === 'true') {
        const tc = chips + (bonus || 0); const nb = await creditChips(phone, tc);
        paymentVerifications.get(mpesaCode).verified = true; broadcastChipStats();
        return res.json({ msg: 'Chips credited (Demo)', chips: tc, newBalance: nb });
    }
    res.json({ msg: 'Payment submitted.', pending: true });
});

app.post('/admin/verify-payment', adminAuth, async (req, res) => {
    const { mpesaCode, approved } = req.body;
    const v = paymentVerifications.get(mpesaCode);
    if (!v || v.verified) return res.status(400).json({ error: 'Invalid or already verified' });
    if (approved) { const tc = v.chips + (v.bonus || 0); const nb = await creditChips(v.phone, tc); v.verified = true; const ps = findSocketByPhone(v.phone); if (ps) ps.emit('chips_credited', { chips: tc, newBalance: nb }); broadcastChipStats(); return res.json({ msg: 'Chips credited', newBalance: nb }); }
    paymentVerifications.delete(mpesaCode); res.json({ msg: 'Rejected' });
});

app.get('/admin/pending-payments', adminAuth, (req, res) => { const p = []; for (const [code, data] of paymentVerifications.entries()) { if (!data.verified) p.push({ mpesaCode: code, phone: data.phone, chips: data.chips, amount: data.amount, timestamp: new Date(data.timestamp).toISOString() }); } res.json({ pending: p }); });

// ─── CHIP WITHDRAWAL SYSTEM ─────────────────────────────────────────────
app.post('/api/chips/withdraw', withdrawLimiter, async (req, res) => {
    const { phone, chips, pin } = req.body;
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone || !chips || chips < MIN_WITHDRAWAL) return res.status(400).json({ error: `Minimum withdrawal is ${MIN_WITHDRAWAL} chips.` });
    if (!pin || !validatePin(pin)) return res.status(400).json({ error: 'PIN must be 4 digits.' });
    const storedPin = await getUserPin(normalizedPhone);
    if (!storedPin || !await verifyPin(pin, storedPin)) return res.status(400).json({ error: 'Invalid PIN.' });
    const balance = await getChipBalance(normalizedPhone);
    const totalDeduction = chips + WITHDRAWAL_FEE;
    if (balance < totalDeduction) return res.status(400).json({ error: `Insufficient chips. Need ${totalDeduction} (${chips} + ${WITHDRAWAL_FEE} fee).` });
    if (!await deductChips(normalizedPhone, totalDeduction)) return res.status(400).json({ error: 'Withdrawal failed.' });
    await burnChips(chips);
    await creditHouseChips(WITHDRAWAL_FEE);
    const withdrawalId = crypto.randomBytes(8).toString('hex');
    withdrawalRequests.set(withdrawalId, { phone: normalizedPhone, chips, fee: WITHDRAWAL_FEE, timestamp: Date.now(), status: 'pending' });
    broadcastChipStats();
    audit('withdrawal_requested', { phone: normalizedPhone, chips, fee: WITHDRAWAL_FEE, withdrawalId });
    res.json({ msg: `Withdrawal of ${chips} chips requested. You'll receive KES ${chips} shortly.`, withdrawalId, newBalance: await getChipBalance(normalizedPhone) });
});

app.get('/admin/pending-withdrawals', adminAuth, (req, res) => {
    const pending = [];
    for (const [id, data] of withdrawalRequests.entries()) { if (data.status === 'pending') pending.push({ id, phone: data.phone, chips: data.chips, fee: data.fee, timestamp: new Date(data.timestamp).toISOString() }); }
    res.json({ pending });
});

app.post('/admin/process-withdrawal', adminAuth, async (req, res) => {
    const { withdrawalId, approved } = req.body;
    const w = withdrawalRequests.get(withdrawalId);
    if (!w) return res.status(404).json({ error: 'Not found' });
    if (w.status !== 'pending') return res.status(400).json({ error: 'Already processed' });
    if (approved) { w.status = 'completed'; const ps = findSocketByPhone(w.phone); if (ps) ps.emit('withdrawal_complete', { chips: w.chips, withdrawalId }); audit('withdrawal_completed', { phone: w.phone, chips: w.chips }); return res.json({ msg: 'Withdrawal approved. Send KES ' + w.chips + ' to ' + w.phone }); }
    w.status = 'rejected'; await creditChips(w.phone, w.chips + w.fee); broadcastChipStats(); const ps = findSocketByPhone(w.phone); if (ps) ps.emit('withdrawal_rejected', { chips: w.chips }); res.json({ msg: 'Withdrawal rejected. Chips refunded.' });
});

app.get('/api/transfers', (req, res) => { const phone = req.query.phone; if (!phone) return res.status(400).json({ error: 'Phone required' }); res.json({ transfers: transferHistory.get(phone) || [] }); });

app.post('/api/reset-pin/request', resetLimiter, async (req, res) => { /* same as before */ });
app.post('/api/reset-pin/verify', async (req, res) => { /* same as before */ });
app.post('/api/reset-pin/set', async (req, res) => { /* same as before */ });
app.get('/api/room/:code', (req, res) => { const room = privateRooms.get((req.params.code || '').toUpperCase()); res.json(room ? { exists: true, playerJoined: !!room.playerSocket } : { exists: false }); });
app.post('/api/check-user', async (req, res) => { const p = normalizePhone(req.body.phone); if (!p) return res.status(400).json({ error: 'Invalid phone.' }); res.json({ exists: await userExists(p) }); });

const checkWinner = (board) => { for (const [a, b, c] of WIN_COMBOS) { if (board[a] && board[a] === board[b] && board[a] === board[c]) return board[a]; } return board.every(Boolean) ? 'DRAW' : null; };

io.use((socket, next) => { const ip = socket.handshake.address; const conns = Array.from(io.sockets.sockets.values()).filter(s => s.handshake.address === ip).length; if (conns > 5) return next(new Error('Too many connections')); next(); });

io.on('connection', (socket) => {
    socket.searching = false; socket.currentRoom = null; socket.authenticated = false; socket.ip = socket.handshake.address;
    broadcastOnlineCount(); broadcastChipStats();
    socket.on('check_user', async ({ phone }) => { const p = normalizePhone(phone); if (!p) return socket.emit('error_msg', 'Invalid phone.'); socket.emit('user_check_result', { exists: await userExists(p), phone: p }); });
    socket.on('register', async ({ phone, pin }) => { /* same registration logic */ });
    socket.on('auth', async ({ phone, pin }) => { /* same auth logic with chips */ });
    socket.on('transfer_chips', async ({ recipientPhone, amount, pin }) => { /* same transfer logic */ });
    socket.on('create_private_room', async () => { /* same */ });
    socket.on('join_private_room', async ({ roomCode }) => { /* same */ });
    socket.on('cancel_private_room', async () => { /* same */ });
    socket.on('find_match', async () => { /* same */ });
    socket.on('cancel_search', async () => { /* same */ });
    socket.on('make_move', ({ gameId, index }) => { /* same */ });
    socket.on('disconnect', async () => { /* same */ });
});

async function finishGame(gameId, game, result) { /* same finish logic */ broadcastChipStats(); }

async function start() {
    try { await redis.connect(); console.log('Redis connected'); } catch(e) { console.warn('Redis unavailable'); }
    await updateCirculationStats();
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => console.log('TicTac Cash running on port', PORT));
}
start();