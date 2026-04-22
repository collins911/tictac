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

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { transports: ['websocket', 'polling'] });

// ─── REDIS (balances only) ────────────────────────────────────────────────
const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error',   e => console.error('Redis error:', e.message));
redis.on('connect', () => console.log('Redis connected'));

// ─── IN-MEMORY STATE ──────────────────────────────────────────────────────
let   waitingSocket = null;          // single socket waiting for opponent
const games         = new Map();     // gameId -> game object
const balances      = new Map();     // phone  -> balance (fallback if Redis down)

// ─── SECURITY ────────────────────────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc:  ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc:    ["'self'", "https://fonts.gstatic.com"],
            connectSrc: ["'self'", "wss:", "ws:", "https:"],
            imgSrc:     ["'self'", "data:"],
            frameSrc:   ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false,
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── RATE LIMITING ────────────────────────────────────────────────────────
const depositLimiter  = rateLimit({ windowMs: 60000, max: 5,  message: { error: 'Too many deposit attempts.' } });
const withdrawLimiter = rateLimit({ windowMs: 60000, max: 3,  message: { error: 'Too many withdrawal attempts.' } });

// ─── CONSTANTS ────────────────────────────────────────────────────────────
const ENTRY_FEE   = 50;
const WIN_PRIZE   = 85;
const DRAW_REFUND = 50;
const WITHDRAW_FEE = 10;
const DEMO_BONUS  = 1000;
const WIN_COMBOS  = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];

// ─── INTASEND ─────────────────────────────────────────────────────────────
const intasend = new IntaSend(
    process.env.INTASEND_PUBLISHABLE_KEY,
    process.env.INTASEND_SECRET_KEY,
    process.env.NODE_ENV !== 'production'
);

// ─── HELPERS ─────────────────────────────────────────────────────────────
const audit = (event, data) =>
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), event, ...data }));

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

// ─── BALANCE (Redis with in-memory fallback) ──────────────────────────────
const getBalance = async (phone) => {
    try {
        if (redis.isReady) {
            const v = await redis.get(`user:${phone}:balance`);
            const bal = parseFloat(v || '0');
            balances.set(phone, bal);
            return bal;
        }
    } catch(e) {}
    return balances.get(phone) || 0;
};

const setBalance = async (phone, amount) => {
    balances.set(phone, amount);
    try {
        if (redis.isReady) await redis.set(`user:${phone}:balance`, String(amount));
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
    const newBal = parseFloat((bal + amount).toFixed(2));
    await setBalance(phone, newBal);
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
    const online    = io.sockets.sockets.size;
    const searching = waitingSocket ? 1 : 0;
    io.emit('online_count', { online, searching });
};

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now(), redis: redis.isReady }));

// ─── DEPOSIT ─────────────────────────────────────────────────────────────
app.post('/mpesa/deposit', depositLimiter, async (req, res) => {
    const { phone, amount } = req.body;
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) return res.status(400).json({ error: 'Invalid phone number.' });
    const parsedAmount = validateAmount(amount);
    if (!parsedAmount) return res.status(400).json({ error: 'Invalid amount.' });
    if (process.env.DEMO_MODE === 'true')
        return res.status(403).json({ error: 'Deposits disabled in demo mode.' });
    try {
        const collection = intasend.collection();
        await collection.mpesaStkPush({
            first_name: 'Player', last_name: '',
            email: `${normalizedPhone}@tictaccash.app`,
            host: process.env.BASE_URL,
            amount: parsedAmount, phone_number: normalizedPhone,
            api_ref: `deposit_${normalizedPhone}_${Date.now()}`,
        });
        audit('deposit_initiated', { phone: normalizedPhone, amount: parsedAmount });
        res.json({ msg: 'STK Prompt Sent! Check your phone.' });
    } catch (err) {
        res.status(500).json({ error: 'Deposit failed. Please try again.' });
    }
});

// ─── WITHDRAWAL ───────────────────────────────────────────────────────────
app.post('/mpesa/withdraw', withdrawLimiter, async (req, res) => {
    const { phone, amount } = req.body;
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) return res.status(400).json({ error: 'Invalid phone number.' });
    const parsedAmount = validateAmount(amount);
    if (!parsedAmount || parsedAmount < 10) return res.status(400).json({ error: 'Minimum withdrawal is KES 10.' });
    if (process.env.DEMO_MODE === 'true')
        return res.status(403).json({ error: 'Withdrawals disabled in demo mode.' });
    const totalDeduct = parsedAmount + WITHDRAW_FEE;
    const deducted = await deductBalance(normalizedPhone, totalDeduct);
    if (!deducted) return res.status(400).json({ error: `Insufficient balance. Need KES ${totalDeduct}.` });
    try {
        const payouts = intasend.payouts();
        await payouts.mpesa({
            currency: 'KES', requires_approval: 'NO',
            transactions: [{ name: 'Player', account: normalizedPhone, amount: String(parsedAmount), narrative: 'TicTacCash Withdrawal' }]
        });
        audit('withdrawal_initiated', { phone: normalizedPhone, amount: parsedAmount });
        res.json({ msg: `Withdrawal of KES ${parsedAmount} initiated.` });
    } catch (err) {
        await creditBalance(normalizedPhone, totalDeduct);
        res.status(500).json({ error: 'Withdrawal failed. Balance refunded.' });
    }
});

app.use((err, req, res, next) => {
    res.status(500).json({ error: 'Internal server error' });
});

// ─── WINNER CHECK ─────────────────────────────────────────────────────────
const checkWinner = (board) => {
    for (const [a, b, c] of WIN_COMBOS) {
        if (board[a] && board[a] === board[b] && board[a] === board[c]) return board[a];
    }
    return board.every(Boolean) ? 'DRAW' : null;
};

// ─── SOCKET EVENTS ────────────────────────────────────────────────────────
io.on('connection', (socket) => {
    broadcastOnlineCount();

    // ── AUTH ──────────────────────────────────────────────────────────────
    socket.on('auth', async ({ phone }) => {
        const normalizedPhone = normalizePhone(phone);
        if (!normalizedPhone) {
            return socket.emit('error_msg', 'Invalid phone number. Use format: 07XXXXXXXX');
        }
        socket.phone = normalizedPhone;
        socket.join(`phone:${normalizedPhone}`);

        const claimed = await getDemoClaimed(normalizedPhone);
        if (!claimed) {
            await creditBalance(normalizedPhone, DEMO_BONUS);
            await setDemoClaimed(normalizedPhone);
            audit('demo_bonus', { phone: normalizedPhone, amount: DEMO_BONUS });
            socket.emit('demo_bonus', { amount: DEMO_BONUS });
        } else {
            const bal = await getBalance(normalizedPhone);
            if (bal < ENTRY_FEE) {
                await creditBalance(normalizedPhone, DEMO_BONUS);
                audit('demo_topup', { phone: normalizedPhone });
                socket.emit('demo_bonus', { amount: DEMO_BONUS });
            }
        }

        const bal = await getBalance(normalizedPhone);
        audit('auth', { phone: normalizedPhone, balance: bal });
        socket.emit('auth_success', { balance: bal.toFixed(2) });
        broadcastOnlineCount();
    });

    // ── FIND MATCH ────────────────────────────────────────────────────────
    socket.on('find_match', async () => {
        if (!socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (socket.searching) return;
        socket.searching = true;
        audit('find_match', { phone: socket.phone });

        const deducted = await deductBalance(socket.phone, ENTRY_FEE);
        if (!deducted) {
            socket.searching = false;
            return socket.emit('error_msg', `Insufficient balance. Need KES ${ENTRY_FEE}.`);
        }

        const newBal = await getBalance(socket.phone);
        socket.emit('balance_update', { balance: newBal.toFixed(2) });

        // ── MATCH IMMEDIATELY if someone is waiting ───────────────────────
        if (waitingSocket && waitingSocket.id !== socket.id && waitingSocket.searching) {
            const opponent = waitingSocket;
            waitingSocket = null;

            opponent.searching = false;
            socket.searching   = false;

            const gameId = `game_${crypto.randomUUID()}`;
            socket.join(gameId);
            opponent.join(gameId);

            const game = {
                board: Array(9).fill(null),
                players: { X: socket.phone,  O: opponent.phone },
                sockets: { X: socket.id,     O: opponent.id    },
                currentTurn: 'X',
            };
            games.set(gameId, game);
            audit('game_started', { gameId, playerX: socket.phone, playerO: opponent.phone });

            io.to(gameId).emit('match_found', {
                gameId,
                playerX: socket.id,
                playerO: opponent.id,
            });
            broadcastOnlineCount();
        } else {
            // No one waiting — put this socket in the waiting slot
            waitingSocket = socket;
            socket.emit('waiting', {});
            broadcastOnlineCount();
        }
    });

    // ── CANCEL SEARCH ─────────────────────────────────────────────────────
    socket.on('cancel_search', async () => {
        if (!socket.searching) return;
        if (waitingSocket && waitingSocket.id === socket.id) waitingSocket = null;
        socket.searching = false;
        await creditBalance(socket.phone, ENTRY_FEE);
        const bal = await getBalance(socket.phone);
        socket.emit('balance_update', { balance: bal.toFixed(2) });
        socket.emit('search_cancelled', {});
        audit('search_cancelled', { phone: socket.phone });
        broadcastOnlineCount();
    });

    // ── MAKE MOVE ─────────────────────────────────────────────────────────
    socket.on('make_move', ({ gameId, index }) => {
        const game = games.get(gameId);
        if (!game) return socket.emit('error_msg', 'Game not found.');

        const mySymbol = game.sockets.X === socket.id ? 'X' : game.sockets.O === socket.id ? 'O' : null;
        if (!mySymbol)              return socket.emit('error_msg', 'Not in this game.');
        if (game.currentTurn !== mySymbol) return socket.emit('error_msg', 'Not your turn.');
        if (typeof index !== 'number' || index < 0 || index > 8) return socket.emit('error_msg', 'Invalid move.');
        if (game.board[index])      return socket.emit('error_msg', 'Cell taken.');

        game.board[index]  = mySymbol;
        game.currentTurn   = mySymbol === 'X' ? 'O' : 'X';

        io.to(gameId).emit('move_made', { index, symbol: mySymbol, nextTurn: game.currentTurn });

        const result = checkWinner(game.board);
        if (result) finishGame(gameId, game, result);
    });

    // ── DISCONNECT ────────────────────────────────────────────────────────
    socket.on('disconnect', async () => {
        // Remove from waiting slot
        if (waitingSocket && waitingSocket.id === socket.id) {
            waitingSocket = null;
            if (socket.phone) await creditBalance(socket.phone, ENTRY_FEE);
        }

        // Handle mid-game disconnect
        for (const [gameId, game] of games.entries()) {
            if (game.sockets.X === socket.id || game.sockets.O === socket.id) {
                const mySymbol       = game.sockets.X === socket.id ? 'X' : 'O';
                const oppSymbol      = mySymbol === 'X' ? 'O' : 'X';
                const oppPhone       = game.players[oppSymbol];
                const oppSocketId    = game.sockets[oppSymbol];
                const oppSocket      = io.sockets.sockets.get(oppSocketId);

                const newBal = await creditBalance(oppPhone, WIN_PRIZE);
                if (oppSocket) {
                    oppSocket.searching = false;
                    oppSocket.emit('balance_update', { balance: newBal.toFixed(2) });
                    oppSocket.emit('game_finished', {
                        result: 'FORFEIT', winner: oppSymbol,
                        winnerSocketId: oppSocketId, prize: WIN_PRIZE,
                    });
                }
                audit('game_forfeit', { gameId, winner: oppPhone });
                games.delete(gameId);
                break;
            }
        }
        broadcastOnlineCount();
    });

    socket.on('get_balance', async () => {
        if (!socket.phone) return;
        const bal = await getBalance(socket.phone);
        socket.emit('balance_update', { balance: bal.toFixed(2) });
    });
});

// ─── FINISH GAME ──────────────────────────────────────────────────────────
async function finishGame(gameId, game, result) {
    games.delete(gameId);
    if (result === 'DRAW') {
        await Promise.all([
            creditBalance(game.players.X, DRAW_REFUND),
            creditBalance(game.players.O, DRAW_REFUND),
        ]);
        const [balX, balO] = await Promise.all([
            getBalance(game.players.X),
            getBalance(game.players.O),
        ]);
        const sX = io.sockets.sockets.get(game.sockets.X);
        const sO = io.sockets.sockets.get(game.sockets.O);
        if (sX) sX.emit('balance_update', { balance: balX.toFixed(2) });
        if (sO) sO.emit('balance_update', { balance: balO.toFixed(2) });
        audit('game_draw', { gameId });
        io.to(gameId).emit('game_finished', { result: 'DRAW', winner: null, winnerSocketId: null, refund: DRAW_REFUND });
    } else {
        const winnerPhone    = game.players[result];
        const winnerSocketId = game.sockets[result];
        const newBal = await creditBalance(winnerPhone, WIN_PRIZE);
        const winnerSocket = io.sockets.sockets.get(winnerSocketId);
        if (winnerSocket) winnerSocket.emit('balance_update', { balance: newBal.toFixed(2) });
        audit('game_won', { gameId, winner: winnerPhone, prize: WIN_PRIZE });
        io.to(gameId).emit('game_finished', { result: 'WIN', winner: result, winnerSocketId, prize: WIN_PRIZE });
    }
    broadcastOnlineCount();
}

// ─── START ────────────────────────────────────────────────────────────────
async function start() {
    try {
        await redis.connect();
    } catch(e) {
        console.warn('Redis unavailable — using in-memory balances only:', e.message);
    }
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => console.log(`TicTac Cash running on port ${PORT}`));
}

start();