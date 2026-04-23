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
    if (redis.isReady) { const keys = await redis.keys('user:*:chips'); for (const key of keys) { const enc = await redis.get(key); if (enc) { const data = decryptChipBalance(enc); if (data) total += data.balance; } } }
    else { for (const bal of chipBalances.values()) total += bal; }
    totalChipsInCirculation = total; broadcastChipStats();
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

// ─── API ENDPOINTS ────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now(), redis: redis.isReady }));
app.get('/api/stats/public', async (req, res) => res.json({ status: 'ok', totalUsers: redis.isReady ? (await redis.keys('user:*:pin')).length : userPins.size, onlinePlayers: io.sockets.sockets.size, activeGames: games.size }));
app.get('/admin/stats', adminLimiter, adminAuth, async (req, res) => { let totalUsers = redis.isReady ? (await redis.keys('user:*:pin')).length : userPins.size; res.json({ totalUsers, chipsInCirculation: totalChipsInCirculation, chipsWithdrawn: totalChipsWithdrawn, houseBalance: houseChipBalance, activeGames: games.size, onlinePlayers: io.sockets.sockets.size, pendingWithdrawals: withdrawalRequests.size }); });
app.get('/admin/count', adminLimiter, adminAuth, async (req, res) => res.json({ totalUsers: redis.isReady ? (await redis.keys('user:*:pin')).length : userPins.size }));

app.post('/api/chips/verify-payment', async (req, res) => {
    const { phone, mpesaCode, chips, amount, bonus } = req.body;
    if (!phone || !mpesaCode || !chips || !amount) return res.status(400).json({ error: 'Missing fields' });
    if (paymentVerifications.has(mpesaCode) && paymentVerifications.get(mpesaCode).verified) return res.status(400).json({ error: 'Code already used' });
    paymentVerifications.set(mpesaCode, { phone, chips, amount, bonus: bonus || 0, timestamp: Date.now(), verified: false });
    if (process.env.DEMO_MODE === 'true') { const tc = chips + (bonus || 0); const nb = await creditChips(phone, tc); paymentVerifications.get(mpesaCode).verified = true; broadcastChipStats(); return res.json({ msg: 'Chips credited (Demo)', chips: tc, newBalance: nb }); }
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

app.post('/api/chips/withdraw', withdrawLimiter, async (req, res) => {
    const { phone, chips, pin } = req.body;
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone || !chips || chips < MIN_WITHDRAWAL) return res.status(400).json({ error: `Min ${MIN_WITHDRAWAL} chips.` });
    if (!pin || !validatePin(pin)) return res.status(400).json({ error: 'PIN must be 4 digits.' });
    const storedPin = await getUserPin(normalizedPhone);
    if (!storedPin || !await verifyPin(pin, storedPin)) return res.status(400).json({ error: 'Invalid PIN.' });
    const balance = await getChipBalance(normalizedPhone);
    const totalDeduction = chips + WITHDRAWAL_FEE;
    if (balance < totalDeduction) return res.status(400).json({ error: `Insufficient chips. Need ${totalDeduction}.` });
    if (!await deductChips(normalizedPhone, totalDeduction)) return res.status(400).json({ error: 'Withdrawal failed.' });
    await burnChips(chips); await creditHouseChips(WITHDRAWAL_FEE);
    const withdrawalId = crypto.randomBytes(8).toString('hex');
    withdrawalRequests.set(withdrawalId, { phone: normalizedPhone, chips, fee: WITHDRAWAL_FEE, timestamp: Date.now(), status: 'pending' });
    broadcastChipStats();
    res.json({ msg: `Withdrawal of ${chips} chips requested.`, withdrawalId, newBalance: await getChipBalance(normalizedPhone) });
});

app.get('/admin/pending-withdrawals', adminAuth, (req, res) => {
    const pending = [];
    for (const [id, data] of withdrawalRequests.entries()) { if (data.status === 'pending') pending.push({ id, phone: data.phone, chips: data.chips, fee: data.fee, timestamp: new Date(data.timestamp).toISOString() }); }
    res.json({ pending });
});

app.post('/admin/process-withdrawal', adminAuth, async (req, res) => {
    const { withdrawalId, approved } = req.body;
    const w = withdrawalRequests.get(withdrawalId);
    if (!w || w.status !== 'pending') return res.status(400).json({ error: 'Invalid' });
    if (approved) { w.status = 'completed'; const ps = findSocketByPhone(w.phone); if (ps) ps.emit('withdrawal_complete', { chips: w.chips }); return res.json({ msg: 'Approved. Send KES ' + w.chips + ' to ' + w.phone }); }
    w.status = 'rejected'; await creditChips(w.phone, w.chips + w.fee); broadcastChipStats(); const ps = findSocketByPhone(w.phone); if (ps) ps.emit('withdrawal_rejected', { chips: w.chips }); res.json({ msg: 'Rejected. Chips refunded.' });
});

app.post('/api/reset-pin/request', resetLimiter, async (req, res) => {
    const { phone } = req.body;
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) return res.status(400).json({ error: 'Invalid phone.' });
    if (!await userExists(normalizedPhone)) return res.status(404).json({ error: 'No account found.' });
    const resetCode = generateResetCode(); const token = generateSecureToken();
    resetTokens.set(token, { phone: normalizedPhone, code: resetCode, expires: Date.now() + 600000, attempts: 0, verified: false, verifyToken: null });
    if (process.env.DEMO_MODE === 'true') return res.json({ msg: 'Demo code', demoCode: resetCode, token });
    res.json({ msg: 'Code sent.', token });
});

app.post('/api/reset-pin/verify', async (req, res) => {
    const { token, code } = req.body;
    if (!token || !code) return res.status(400).json({ error: 'Token and code required.' });
    const resetData = resetTokens.get(token);
    if (!resetData || resetData.expires < Date.now()) return res.status(400).json({ error: 'Invalid or expired.' });
    if (resetData.attempts >= 3) { resetTokens.delete(token); return res.status(400).json({ error: 'Too many attempts.' }); }
    if (resetData.code !== code) { resetData.attempts++; return res.status(400).json({ error: 'Invalid code.' }); }
    const verifyToken = generateSecureToken(); resetData.verified = true; resetData.verifyToken = verifyToken;
    res.json({ msg: 'Verified.', verifyToken });
});

app.post('/api/reset-pin/set', async (req, res) => {
    const { token, verifyToken, newPin } = req.body;
    if (!token || !verifyToken || !newPin) return res.status(400).json({ error: 'Missing fields.' });
    if (!validatePin(newPin)) return res.status(400).json({ error: 'PIN must be 4 digits.' });
    const resetData = resetTokens.get(token);
    if (!resetData || !resetData.verified || resetData.verifyToken !== verifyToken) return res.status(400).json({ error: 'Invalid session.' });
    await setUserPin(resetData.phone, newPin); resetTokens.delete(token); resetLoginAttempts(resetData.phone);
    res.json({ msg: 'PIN reset successful.' });
});

app.get('/api/room/:code', (req, res) => { const room = privateRooms.get((req.params.code || '').toUpperCase()); res.json(room ? { exists: true, playerJoined: !!room.playerSocket } : { exists: false }); });
app.post('/api/check-user', async (req, res) => { const p = normalizePhone(req.body.phone); if (!p) return res.status(400).json({ error: 'Invalid phone.' }); res.json({ exists: await userExists(p) }); });

const checkWinner = (board) => { for (const [a, b, c] of WIN_COMBOS) { if (board[a] && board[a] === board[b] && board[a] === board[c]) return board[a]; } return board.every(Boolean) ? 'DRAW' : null; };

// ─── SOCKET.IO ────────────────────────────────────────────────────────────
io.use((socket, next) => { const ip = socket.handshake.address; const conns = Array.from(io.sockets.sockets.values()).filter(s => s.handshake.address === ip).length; if (conns > 5) return next(new Error('Too many connections')); next(); });

io.on('connection', (socket) => {
    socket.searching = false; socket.currentRoom = null; socket.authenticated = false; socket.ip = socket.handshake.address;
    console.log('New connection:', socket.id);
    broadcastOnlineCount(); broadcastChipStats();

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
        if (await userExists(normalizedPhone)) return socket.emit('error_msg', 'User already exists. Please login.');
        const weakPins = ['0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999', '1234'];
        if (weakPins.includes(pin)) return socket.emit('error_msg', 'Please choose a more secure PIN.');
        await setUserPin(normalizedPhone, pin);
        await setUserCreatedAt(normalizedPhone);
        await creditChips(normalizedPhone, DEMO_CHIPS);
        audit('user_registered', { phone: normalizedPhone });
        socket.emit('registration_success', { phone: normalizedPhone });
        console.log('New user registered:', normalizedPhone);
    });

    socket.on('auth', async ({ phone, pin }) => {
        const normalizedPhone = normalizePhone(phone);
        if (!normalizedPhone) return socket.emit('error_msg', 'Invalid phone number.');
        if (!validatePin(pin)) return socket.emit('error_msg', 'PIN must be 4 digits.');
        const attemptCheck = checkLoginAttempts(normalizedPhone);
        if (!attemptCheck.allowed) return socket.emit('error_msg', attemptCheck.reason);
        const storedPin = await getUserPin(normalizedPhone);
        if (!storedPin) return socket.emit('error_msg', 'User not found. Please register first.');
        const pinValid = await verifyPin(pin, storedPin);
        if (!pinValid) { recordFailedLogin(normalizedPhone); audit('auth_failed', { phone: normalizedPhone }); return socket.emit('error_msg', 'Invalid PIN.'); }
        resetLoginAttempts(normalizedPhone);
        socket.phone = normalizedPhone;
        socket.authenticated = true;
        socket.join(`phone:${normalizedPhone}`);
        let chips = await getChipBalance(normalizedPhone);
        if (chips < ENTRY_FEE) { await creditChips(normalizedPhone, DEMO_CHIPS); chips = await getChipBalance(normalizedPhone); socket.emit('demo_bonus', { chips: DEMO_CHIPS }); }
        audit('auth_success', { phone: normalizedPhone });
        socket.emit('auth_success', { chips });
        broadcastOnlineCount();
        console.log('Auth success:', normalizedPhone, 'Chips:', chips);
    });

    socket.on('transfer_chips', async ({ recipientPhone, amount, pin }) => {
        if (!socket.authenticated || !socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        const storedPin = await getUserPin(socket.phone);
        if (!storedPin || !await verifyPin(pin, storedPin)) return socket.emit('error_msg', 'Invalid PIN.');
        if (amount < 10 || amount > 10000) return socket.emit('error_msg', 'Min 10, max 10000 chips.');
        const fee = Math.max(Math.floor(amount * TRANSFER_FEE_PERCENT / 100), MIN_TRANSFER_FEE);
        const totalDeduction = amount + fee;
        const senderBalance = await getChipBalance(socket.phone);
        if (senderBalance < totalDeduction) return socket.emit('error_msg', `Insufficient chips. Need ${totalDeduction}.`);
        const normalizedRecipient = normalizePhone(recipientPhone);
        if (!normalizedRecipient || normalizedRecipient === socket.phone || !await userExists(normalizedRecipient)) return socket.emit('error_msg', 'Invalid recipient.');
        if (!await deductChips(socket.phone, totalDeduction)) return socket.emit('error_msg', 'Transfer failed.');
        await creditChips(normalizedRecipient, amount);
        await creditHouseChips(fee);
        const transferId = crypto.randomBytes(8).toString('hex');
        const transfer = { id: transferId, type: 'sent', counterparty: normalizedRecipient, amount, fee, timestamp: Date.now(), status: 'completed' };
        const receivedTransfer = { id: transferId, type: 'received', counterparty: socket.phone, amount, timestamp: Date.now(), status: 'completed' };
        let sh = transferHistory.get(socket.phone) || []; sh.unshift(transfer); if (sh.length > 50) sh = sh.slice(0, 50); transferHistory.set(socket.phone, sh);
        let rh = transferHistory.get(normalizedRecipient) || []; rh.unshift(receivedTransfer); if (rh.length > 50) rh = rh.slice(0, 50); transferHistory.set(normalizedRecipient, rh);
        const rs = findSocketByPhone(normalizedRecipient); if (rs) rs.emit('chips_received', { from: socket.phone, amount, transferId });
        socket.emit('transfer_complete', { to: normalizedRecipient, amount, fee, transferId, newBalance: await getChipBalance(socket.phone) });
        broadcastChipStats();
    });

    socket.on('create_private_room', async () => {
        if (!socket.authenticated || !socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (!await deductChips(socket.phone, ENTRY_FEE)) return socket.emit('error_msg', `Insufficient chips. Need ${ENTRY_FEE}.`);
        socket.emit('balance_update', { chips: await getChipBalance(socket.phone) });
        const roomCode = generateRoomCode();
        privateRooms.set(roomCode, { code: roomCode, creator: socket.phone, creatorSocket: socket.id, playerSocket: null, playerPhone: null, createdAt: Date.now(), gameStarted: false });
        socket.currentRoom = roomCode; socket.join(`room:${roomCode}`);
        socket.emit('room_created', { roomCode, chips: await getChipBalance(socket.phone) });
        socket.emit('waiting_for_opponent', { roomCode });
    });

    socket.on('join_private_room', async ({ roomCode }) => {
        if (!socket.authenticated || !socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        const code = roomCode.toUpperCase(); const room = privateRooms.get(code);
        if (!room || room.gameStarted || room.playerSocket || room.creator === socket.phone) return socket.emit('room_error', { error: 'Cannot join this room.' });
        if (!await deductChips(socket.phone, ENTRY_FEE)) return socket.emit('error_msg', `Insufficient chips. Need ${ENTRY_FEE}.`);
        socket.emit('balance_update', { chips: await getChipBalance(socket.phone) });
        room.playerSocket = socket.id; room.playerPhone = socket.phone; room.gameStarted = true;
        socket.currentRoom = code; socket.join(`room:${code}`);
        const gameId = `private_${code}_${Date.now()}`;
        games.set(gameId, { board: Array(9).fill(null), players: { X: room.creator, O: socket.phone }, sockets: { X: room.creatorSocket, O: socket.id }, currentTurn: 'X', isPrivate: true, roomCode: code });
        socket.emit('private_match_found', { gameId, mySymbol: 'O', opponent: room.creator });
        const cs = io.sockets.sockets.get(room.creatorSocket); if (cs) cs.emit('private_match_found', { gameId, mySymbol: 'X', opponent: socket.phone });
    });

    socket.on('cancel_private_room', async () => {
        if (!socket.authenticated) return;
        const room = privateRooms.get(socket.currentRoom);
        if (room && room.creatorSocket === socket.id && !room.gameStarted) {
            privateRooms.delete(socket.currentRoom); socket.currentRoom = null; socket.leave(`room:${socket.currentRoom}`);
            await creditChips(socket.phone, ENTRY_FEE); socket.emit('balance_update', { chips: await getChipBalance(socket.phone) }); socket.emit('room_cancelled', {});
        }
    });

    socket.on('find_match', async () => {
        if (!socket.authenticated || !socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (socket.searching || socket.currentRoom) return socket.emit('error_msg', 'Cannot search now.');
        if (!await deductChips(socket.phone, ENTRY_FEE)) return socket.emit('error_msg', 'Insufficient chips.');
        socket.searching = true;
        socket.emit('balance_update', { chips: await getChipBalance(socket.phone) });
        if (waitingSocket && waitingSocket.id !== socket.id && waitingSocket.searching) {
            const opponent = waitingSocket; waitingSocket = null;
            opponent.searching = false; socket.searching = false;
            const gameId = 'game_' + crypto.randomUUID();
            socket.join(gameId); opponent.join(gameId);
            games.set(gameId, { board: Array(9).fill(null), players: { X: socket.phone, O: opponent.phone }, sockets: { X: socket.id, O: opponent.id }, currentTurn: 'X', isPrivate: false });
            io.to(gameId).emit('match_found', { gameId, playerX: socket.id, playerO: opponent.id });
            broadcastOnlineCount();
        } else { waitingSocket = socket; socket.emit('waiting', {}); broadcastOnlineCount(); }
    });

    socket.on('cancel_search', async () => {
        if (!socket.authenticated || !socket.searching) return;
        if (waitingSocket && waitingSocket.id === socket.id) waitingSocket = null;
        socket.searching = false;
        await creditChips(socket.phone, ENTRY_FEE); socket.emit('balance_update', { chips: await getChipBalance(socket.phone) }); socket.emit('search_cancelled', {}); broadcastOnlineCount();
    });

    socket.on('make_move', ({ gameId, index }) => {
        const game = games.get(gameId);
        if (!game || game.board[index] || index < 0 || index > 8) return;
        const mySymbol = game.sockets.X === socket.id ? 'X' : game.sockets.O === socket.id ? 'O' : null;
        if (!mySymbol || game.currentTurn !== mySymbol) return;
        game.board[index] = mySymbol; game.currentTurn = mySymbol === 'X' ? 'O' : 'X';
        io.to(gameId).emit('move_made', { index, symbol: mySymbol, nextTurn: game.currentTurn });
        const result = checkWinner(game.board);
        if (result) finishGame(gameId, game, result);
    });

    socket.on('disconnect', async () => {
        if (socket.currentRoom) { const room = privateRooms.get(socket.currentRoom); if (room && !room.gameStarted) privateRooms.delete(socket.currentRoom); }
        if (waitingSocket && waitingSocket.id === socket.id) { waitingSocket = null; if (socket.phone && socket.searching) await creditChips(socket.phone, ENTRY_FEE); }
        socket.searching = false; socket.authenticated = false;
        for (const [gameId, game] of games.entries()) {
            if (game.sockets.X === socket.id || game.sockets.O === socket.id) {
                const oppSymbol = game.sockets.X === socket.id ? 'O' : 'X';
                const oppSocket = io.sockets.sockets.get(game.sockets[oppSymbol]);
                const newBal = await creditChips(game.players[oppSymbol], WIN_PRIZE);
                if (oppSocket) { oppSocket.emit('balance_update', { chips: newBal }); oppSocket.emit('game_finished', { result: 'FORFEIT', winner: oppSymbol, winnerSocketId: game.sockets[oppSymbol], prize: WIN_PRIZE }); }
                games.delete(gameId); break;
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
        const [bX, bO] = await Promise.all([getChipBalance(game.players.X), getChipBalance(game.players.O)]);
        const sX = io.sockets.sockets.get(game.sockets.X), sO = io.sockets.sockets.get(game.sockets.O);
        if (sX) sX.emit('balance_update', { chips: bX }); if (sO) sO.emit('balance_update', { chips: bO });
        io.to(gameId).emit('game_finished', { result: 'DRAW', refund: DRAW_REFUND });
    } else {
        const newBal = await creditChips(game.players[result], WIN_PRIZE);
        const ws = io.sockets.sockets.get(game.sockets[result]);
        if (ws) ws.emit('balance_update', { chips: newBal });
        io.to(gameId).emit('game_finished', { result: 'WIN', winner: result, winnerSocketId: game.sockets[result], prize: WIN_PRIZE });
    }
    broadcastOnlineCount(); broadcastChipStats();
}

async function start() {
    try { await redis.connect(); console.log('Redis connected'); } catch(e) { console.warn('Redis unavailable'); }
    await updateCirculationStats();
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => console.log('TicTac Cash running on port', PORT));
}
start();