require('dotenv').config();
const express  = require('express');
const http     = require('http');
const { Server } = require('socket.io');
const { createClient } = require('redis');
const { createAdapter } = require('@socket.io/redis-adapter');
const IntaSend = require('intasend-node');
const helmet   = require('helmet');
const rateLimit = require('express-rate-limit');
const path     = require('path');
const crypto   = require('crypto');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { 
    transports: ['websocket', 'polling'],
    connectionStateRecovery: {} 
});

// ─── REDIS SETUP ──────────────────────────────────────────────────────────
const redis = createClient({ url: process.env.REDIS_URL });
const subClient = redis.duplicate();

redis.on('error',   e => console.error('Redis error:', e.message));
subClient.on('error', e => console.error('Redis Sub error:', e.message));

// ─── STATE ────────────────────────────────────────────────────────────────
const games    = new Map(); // Game state (tracked per instance)
const balances = new Map(); // Fallback balances

// ─── SECURITY & MIDDLEWARE ────────────────────────────────────────────────
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

const depositLimiter  = rateLimit({ windowMs: 60000, max: 5 });
const withdrawLimiter = rateLimit({ windowMs: 60000, max: 3 });

// ─── CONSTANTS ────────────────────────────────────────────────────────────
const ENTRY_FEE = 50, WIN_PRIZE = 85, DRAW_REFUND = 50, WITHDRAW_FEE = 10, DEMO_BONUS = 1000;
const WIN_COMBOS = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];

const intasend = new IntaSend(
    process.env.INTASEND_PUBLISHABLE_KEY,
    process.env.INTASEND_SECRET_KEY,
    process.env.NODE_ENV !== 'production'
);

// ─── HELPERS ──────────────────────────────────────────────────────────────
const audit = (event, data) => console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...data }));

const normalizePhone = (phone) => {
    const c = String(phone).replace(/\D/g, '');
    if (/^254\d{9}$/.test(c)) return c;
    if (/^0\d{9}$/.test(c))   return '254' + c.slice(1);
    if (/^\d{9}$/.test(c))    return '254' + c;
    return null;
};

const checkWinner = (board) => {
    for (const [a, b, c] of WIN_COMBOS) {
        if (board[a] && board[a] === board[b] && board[a] === board[c]) return board[a];
    }
    return board.every(Boolean) ? 'DRAW' : null;
};

// ─── BALANCE LOGIC (Redis-backed) ─────────────────────────────────────────
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
    try { if (redis.isReady) await redis.set(`user:${phone}:balance`, String(amount)); } catch(e) {}
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

// ─── BROADCAST HELPERS ────────────────────────────────────────────────────
const broadcastOnlineCount = async () => {
    const sockets = await io.fetchSockets();
    const online = sockets.length;
    const waiting = await redis.get('matchmaking:waiting');
    io.emit('online_count', { online, searching: waiting ? 1 : 0 });
};

// ─── SOCKET.IO LOGIC ──────────────────────────────────────────────────────
io.on('connection', (socket) => {
    broadcastOnlineCount();

    socket.on('auth', async ({ phone }) => {
        const normalized = normalizePhone(phone);
        if (!normalized) return socket.emit('error_msg', 'Invalid phone format.');
        
        socket.phone = normalized;
        socket.join(`phone:${normalized}`);

        // Demo logic
        const claimed = await redis.get(`user:${normalized}:demo_claimed`);
        if (!claimed) {
            await creditBalance(normalized, DEMO_BONUS);
            await redis.set(`user:${normalized}:demo_claimed`, '1');
            socket.emit('demo_bonus', { amount: DEMO_BONUS });
        }

        const bal = await getBalance(normalized);
        socket.emit('auth_success', { balance: bal.toFixed(2) });
    });

    socket.on('find_match', async () => {
        if (!socket.phone || socket.searching) return;

        const deducted = await deductBalance(socket.phone, ENTRY_FEE);
        if (!deducted) return socket.emit('error_msg', `Insufficient balance.`);

        socket.searching = true;
        const opponentPhone = await redis.get('matchmaking:waiting');

        if (opponentPhone && opponentPhone !== socket.phone) {
            const claimed = await redis.del('matchmaking:waiting');
            if (claimed) {
                const gameId = `game_${crypto.randomUUID()}`;
                
                // Alert both players via phone rooms
                io.to(`phone:${socket.phone}`).to(`phone:${opponentPhone}`).emit('match_found', {
                    gameId, playerX: socket.phone, playerO: opponentPhone
                });

                games.set(gameId, {
                    board: Array(9).fill(null),
                    players: { X: socket.phone, O: opponentPhone },
                    currentTurn: 'X',
                });
            }
        } else {
            await redis.set('matchmaking:waiting', socket.phone, { EX: 45 });
            socket.emit('waiting', {});
        }
        broadcastOnlineCount();
    });

    socket.on('make_move', ({ gameId, index }) => {
        const game = games.get(gameId);
        if (!game) return;

        const symbol = game.players.X === socket.phone ? 'X' : 'O';
        if (game.currentTurn !== symbol || game.board[index]) return;

        game.board[index] = symbol;
        game.currentTurn = symbol === 'X' ? 'O' : 'X';

        io.to(`phone:${game.players.X}`).to(`phone:${game.players.O}`).emit('move_made', { 
            index, symbol, nextTurn: game.currentTurn 
        });

        const result = checkWinner(game.board);
        if (result) finishGame(gameId, game, result);
    });

    socket.on('disconnect', async () => {
        const waiting = await redis.get('matchmaking:waiting');
        if (waiting === socket.phone) await redis.del('matchmaking:waiting');
        broadcastOnlineCount();
    });
});

async function finishGame(gameId, game, result) {
    games.delete(gameId);
    if (result === 'DRAW') {
        await Promise.all([creditBalance(game.players.X, DRAW_REFUND), creditBalance(game.players.O, DRAW_REFUND)]);
    } else {
        await creditBalance(game.players[result], WIN_PRIZE);
    }
    
    io.to(`phone:${game.players.X}`).to(`phone:${game.players.O}`).emit('game_finished', { result });
    broadcastOnlineCount();
}

// ─── START SERVER ─────────────────────────────────────────────────────────
async function start() {
    try {
        await Promise.all([redis.connect(), subClient.connect()]);
        io.adapter(createAdapter(redis, subClient));
        console.log('Redis and Adapter connected');
    } catch(e) { console.warn('Matchmaking limited:', e.message); }
    
    server.listen(process.env.PORT || 3000, () => console.log(`Server running`));
}
start();