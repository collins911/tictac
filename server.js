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

// ─── REDIS ────────────────────────────────────────────────────────────────
const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error',   e => console.error('Redis error:', e.message));
redis.on('connect', () => console.log('Redis connected'));

// ─── IN-MEMORY STATE ──────────────────────────────────────────────────────
let   waitingSocket = null;
const games         = new Map();
const balances      = new Map();

// ─── SECURITY & MIDDLEWARE ───────────────────────────────────────────────
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

// ─── CONSTANTS ────────────────────────────────────────────────────────────
const ENTRY_FEE    = 50;
const WIN_PRIZE    = 85;
const DRAW_REFUND  = 50;
const DEMO_BONUS   = 1000;
const WIN_COMBOS   = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];

// ─── HELPERS ─────────────────────────────────────────────────────────────
const audit = (event, data) => console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...data }));

const normalizePhone = (phone) => {
    const c = String(phone).replace(/\D/g, '');
    if (/^254\d{9}$/.test(c)) return c;
    if (/^0\d{9}$/.test(c))   return '254' + c.slice(1);
    if (/^\d{9}$/.test(c))    return '254' + c;
    return null;
};

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

const broadcastOnlineCount = () => {
    const online    = io.sockets.sockets.size;
    const searching = waitingSocket ? 1 : 0;
    io.emit('online_count', { online, searching });
};

// ─── SOCKET LOGIC ─────────────────────────────────────────────────────────
io.on('connection', (socket) => {
    broadcastOnlineCount();

    socket.on('auth', async ({ phone }) => {
        const normalized = normalizePhone(phone);
        if (!normalized) return socket.emit('error_msg', 'Invalid phone number.');
        socket.phone = normalized;
        const bal = await getBalance(normalized);
        if (bal < ENTRY_FEE) await creditBalance(normalized, DEMO_BONUS);
        const finalBal = await getBalance(normalized);
        socket.emit('auth_success', { balance: finalBal.toFixed(2) });
    });

    socket.on('find_match', async () => {
        if (!socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (socket.searching) return;

        // DEBUG: Track matchmaking attempts
        console.log(`[match] phone=${socket.phone} searching=${socket.searching} waiting=${waitingSocket?.id}`);

        socket.searching = true;

        try {
            const deducted = await deductBalance(socket.phone, ENTRY_FEE);
            if (!deducted) {
                socket.searching = false;
                return socket.emit('error_msg', `Insufficient balance. Need KES ${ENTRY_FEE}`);
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

                io.to(gameId).emit('match_found', { gameId, players: game.players });
                opponent.emit('init_game', { symbol: 'X', turn: 'X' });
                socket.emit('init_game', { symbol: 'O', turn: 'X' });
                
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
                finishGame(gameId, game, game.sockets.X === socket.id ? 'O' : 'X');
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

    const sX = io.sockets.sockets.get(game.sockets.X);
    const sO = io.sockets.sockets.get(game.sockets.O);
    
    // Explicitly reset flags for both players
    if (sX) { sX.searching = false; sX.leave(gameId); }
    if (sO) { sO.searching = false; sO.leave(gameId); }

    if (result === 'DRAW') {
        await Promise.all([creditBalance(game.players.X, DRAW_REFUND), creditBalance(game.players.O, DRAW_REFUND)]);
        io.to(gameId).emit('game_finished', { result: 'DRAW', prize: DRAW_REFUND });
    } else {
        const winnerPhone = game.players[result];
        await creditBalance(winnerPhone, WIN_PRIZE);
        io.to(gameId).emit('game_finished', { result: 'WIN', winner: result, prize: WIN_PRIZE });
    }
    
    if (sX) sX.emit('balance_update', { balance: (await getBalance(game.players.X)).toFixed(2) });
    if (sO) sO.emit('balance_update', { balance: (await getBalance(game.players.O)).toFixed(2) });
}

async function start() {
    try { await redis.connect(); } catch(e) { console.warn('Redis unavailable'); }
    server.listen(process.env.PORT || 3000, () => console.log('Server live'));
}
start();