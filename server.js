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

// ─── ONLINE COUNT ─────────────────────────────────────────────────────────
const broadcastOnlineCount = () => {
    const online    = io.sockets.sockets.size;
    const searching = waitingSocket ? 1 : 0;
    io.emit('online_count', { online, searching });
};

// ─── SOCKET LOGIC ─────────────────────────────────────────────────────────
io.on('connection', (socket) => {
    broadcastOnlineCount();

    socket.on('auth', async ({ phone }) => {
        const normalizedPhone = normalizePhone(phone);
        if (!normalizedPhone) return socket.emit('error_msg', 'Invalid phone number.');
        socket.phone = normalizedPhone;
        const bal = await getBalance(normalizedPhone);
        if (bal < ENTRY_FEE) {
            await creditBalance(normalizedPhone, DEMO_BONUS);
            audit('demo_topup', { phone: normalizedPhone });
            socket.emit('demo_bonus', { amount: DEMO_BONUS });
        }
        const updatedBal = await getBalance(normalizedPhone);
        socket.emit('auth_success', { balance: updatedBal.toFixed(2) });
    });

    socket.on('find_match', async () => {
        if (!socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (socket.searching) return;

        // 🔴 FIX: Debug Logging
        console.log(`[find_match] socket.phone=${socket.phone}, searching=${socket.searching}, waitingSocket=${waitingSocket?.id}`);

        socket.searching = true;

        // 🔴 FIX: Wrapped in try-finally to ensure state reset on error
        try {
            const deducted = await deductBalance(socket.phone, ENTRY_FEE);
            if (!deducted) {
                socket.searching = false;
                return socket.emit('error_msg', `Insufficient balance. Need KES ${ENTRY_FEE}.`);
            }

            if (waitingSocket && waitingSocket.id !== socket.id && waitingSocket.searching) {
                const opponent = waitingSocket;
                waitingSocket = null;
                
                opponent.searching = false;
                socket.searching = false;

                const gameId = `game_${crypto.randomUUID()}`;
                socket.join(gameId);
                opponent.join(gameId);

                const game = {
                    id: gameId,
                    players: { X: opponent.phone, O: socket.phone },
                    sockets: { X: opponent.id,    O: socket.id },
                    board: Array(9).fill(null),
                    turn: 'X',
                    active: true
                };
                games.set(gameId, game);

                io.to(gameId).emit('match_found', { 
                    gameId, 
                    opponent: { X: opponent.phone, O: socket.phone }
                });

                opponent.emit('init_game', { symbol: 'X', turn: 'X' });
                socket.emit('init_game', { symbol: 'O', turn: 'X' });
                
                audit('game_started', { gameId, playerX: opponent.phone, playerO: socket.phone });
                broadcastOnlineCount();
            } else {
                waitingSocket = socket;
                socket.emit('waiting', {});
                broadcastOnlineCount();
            }
        } catch (err) {
            console.error("Matchmaking error:", err);
            socket.searching = false; 
        }
    });

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

    socket.on('make_move', ({ gameId, index }) => {
        const game = games.get(gameId);
        if (!game || !game.active) return;
        const symbol = game.sockets.X === socket.id ? 'X' : (game.sockets.O === socket.id ? 'O' : null);
        if (!symbol || game.turn !== symbol || game.board[index]) return;

        game.board[index] = symbol;
        const winner = checkWinner(game.board);
        const isDraw = !winner && !game.board.includes(null);

        if (winner || isDraw) {
            game.active = false;
            io.to(gameId).emit('update_board', { board: game.board, turn: null });
            finishGame(gameId, game, winner || 'DRAW');
        } else {
            game.turn = symbol === 'X' ? 'O' : 'X';
            io.to(gameId).emit('update_board', { board: game.board, turn: game.turn });
        }
    });

    socket.on('disconnect', async () => {
        if (waitingSocket && waitingSocket.id === socket.id) {
            waitingSocket = null;
            if (socket.phone) await creditBalance(socket.phone, ENTRY_FEE);
        }
        for (const [gameId, game] of games.entries()) {
            if (game.sockets.X === socket.id || game.sockets.O === socket.id) {
                const opponentSymbol = game.sockets.X === socket.id ? 'O' : 'X';
                finishGame(gameId, game, opponentSymbol);
                break;
            }
        }
        broadcastOnlineCount();
    });
});

function checkWinner(board) {
    for (const [a, b, c] of WIN_COMBOS) {
        if (board[a] && board[a] === board[b] && board[a] === board[c]) return board[a];
    }
    return null;
}

async function finishGame(gameId, game, result) {
    games.delete(gameId);

    // 🔴 FIX: Explicitly clean up socket game references 
    const sX = io.sockets.sockets.get(game.sockets.X);
    const sO = io.sockets.sockets.get(game.sockets.O);
    if (sX) { sX.searching = false; sX.leave(gameId); }
    if (sO) { sO.searching = false; sO.leave(gameId); }

    if (result === 'DRAW') {
        await Promise.all([
            creditBalance(game.players.X, DRAW_REFUND),
            creditBalance(game.players.O, DRAW_REFUND)
        ]);
        const [balX, balO] = await Promise.all([
            getBalance(game.players.X),
            getBalance(game.players.O),
        ]);
        if (sX) sX.emit('balance_update', { balance: balX.toFixed(2) });
        if (sO) sO.emit('balance_update', { balance: balO.toFixed(2) });
        io.to(gameId).emit('game_finished', { result: 'DRAW', refund: DRAW_REFUND });
    } else {
        const winnerPhone = game.players[result];
        const newBal = await creditBalance(winnerPhone, WIN_PRIZE);
        const winnerSocket = io.sockets.sockets.get(game.sockets[result]);
        if (winnerSocket) winnerSocket.emit('balance_update', { balance: newBal.toFixed(2) });
        io.to(gameId).emit('game_finished', { result: 'WIN', winner: result, prize: WIN_PRIZE });
    }
    broadcastOnlineCount();
}

async function start() {
    try { await redis.connect(); } catch(e) { console.warn('Redis unavailable'); }
    server.listen(process.env.PORT || 3000, () => console.log('Server live'));
}
start();