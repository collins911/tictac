require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { createAdapter } = require('@socket.io/redis-adapter');
const { createClient } = require('redis');
const IntaSend = require('intasend-node');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    transports: ['websocket', 'polling'],
});

// ─── REDIS CLIENTS ────────────────────────────────────────────────────────
const redis    = createClient({ url: process.env.REDIS_URL || 'redis://127.0.0.1:6380' });
const redisPub = createClient({ url: process.env.REDIS_URL || 'redis://127.0.0.1:6380' });
const redisSub = createClient({ url: process.env.REDIS_URL || 'redis://127.0.0.1:6380' });

// ─── SECURITY HEADERS ────────────────────────────────────────────────────
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
        },
    },
    crossOriginEmbedderPolicy: false,
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── RATE LIMITING ────────────────────────────────────────────────────────
const depositLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { error: 'Too many deposit attempts. Please wait a minute.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const withdrawLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 3,
    message: { error: 'Too many withdrawal attempts. Please wait a minute.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// ─── CONSTANTS ────────────────────────────────────────────────────────────
const ENTRY_FEE  = 50;
const WIN_PRIZE  = 85;
const DRAW_REFUND = 50;
const WITHDRAW_FEE = 10;
const DEMO_BONUS = 1000;
const WIN_COMBOS = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];

// ─── INTASEND CLIENT ─────────────────────────────────────────────────────
const intasend = new IntaSend(
    process.env.INTASEND_PUBLISHABLE_KEY,
    process.env.INTASEND_SECRET_KEY,
    process.env.NODE_ENV !== 'production'
);

// ─── HELPERS ─────────────────────────────────────────────────────────────
const getBalance = async (phone) =>
    parseFloat(await redis.get(`user:${phone}:balance`) || '0');

const deductBalance = async (phone, amount) => {
    const script = `
        local bal = tonumber(redis.call('GET', KEYS[1])) or 0
        if bal < tonumber(ARGV[1]) then return -1 end
        local newbal = bal - tonumber(ARGV[1])
        redis.call('SET', KEYS[1], tostring(newbal))
        return 1
    `;
    const result = await redis.eval(script, {
        keys: [`user:${phone}:balance`],
        arguments: [String(amount)],
    });
    return result === 1;
};

const creditBalance = async (phone, amount) => {
    const script = `
        local bal = tonumber(redis.call('GET', KEYS[1])) or 0
        local newbal = bal + tonumber(ARGV[1])
        redis.call('SET', KEYS[1], tostring(newbal))
        return tostring(newbal)
    `;
    return await redis.eval(script, {
        keys: [`user:${phone}:balance`],
        arguments: [String(amount)],
    });
};

const normalizePhone = (phone) => {
    const cleaned = String(phone).replace(/\D/g, '');
    // Full 254 format — any Kenyan carrier (Safaricom 2547xx, Airtel 2547x/2541x, Telkom 2547x/2540x)
    if (/^254\d{9}$/.test(cleaned)) return cleaned;
    // Local 0xx format
    if (/^0\d{9}$/.test(cleaned)) return '254' + cleaned.slice(1);
    // Without leading 0 or 254
    if (/^\d{9}$/.test(cleaned)) return '254' + cleaned;
    return null;
};

const validateAmount = (amount) => {
    const parsed = parseInt(amount, 10);
    if (typeof parsed !== 'number') return null;
    if (!isFinite(parsed)) return null;
    if (parsed <= 0) return null;
    if (parsed > 100000) return null;
    return parsed;
};

const audit = (event, data) => {
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), event, ...data }));
};

// ─── GAME STATE IN REDIS ──────────────────────────────────────────────────
const saveGame = async (gameId, game) => {
    await redis.set(`game:${gameId}`, JSON.stringify(game), { EX: 3600 });
};
const getGame = async (gameId) => {
    const raw = await redis.get(`game:${gameId}`);
    return raw ? JSON.parse(raw) : null;
};
const deleteGame = async (gameId) => {
    await redis.del(`game:${gameId}`);
};

// ─── ONLINE PLAYERS COUNT ─────────────────────────────────────────────────
const broadcastOnlineCount = async () => {
    const searching = await redis.lLen('matchmaking_queue');
    const online = io.sockets.sockets.size;
    io.emit('online_count', { online, searching });
};

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

// ─── DEPOSIT: STK PUSH ────────────────────────────────────────────────────
app.post('/mpesa/deposit', depositLimiter, async (req, res) => {
    const { phone, amount } = req.body;

    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) {
        return res.status(400).json({ error: 'Invalid phone number format. Use 2547XXXXXXXX.' });
    }

    const parsedAmount = validateAmount(amount);
    if (!parsedAmount) {
        return res.status(400).json({ error: 'Amount must be a positive number between KES 1 and KES 100,000.' });
    }

    if (process.env.DEMO_MODE === 'true') {
        return res.status(403).json({ error: 'Deposits disabled in demo mode. Use your free KES 1,000 demo balance.' });
    }

    try {
        const collection = intasend.collection();
        const resp = await collection.mpesaStkPush({
            first_name: 'Player',
            last_name: '',
            email: `${normalizedPhone}@tictaccash.app`,
            host: process.env.BASE_URL,
            amount: parsedAmount,
            phone_number: normalizedPhone,
            api_ref: `deposit_${normalizedPhone}_${Date.now()}`,
        });

        audit('deposit_initiated', { phone: normalizedPhone, amount: parsedAmount });

        await redis.set(
            `deposit:${resp.invoice?.invoice_id}`,
            JSON.stringify({ phone: normalizedPhone, amount: parsedAmount }),
            { EX: 3600 }
        );

        res.json({ msg: 'STK Prompt Sent! Check your phone.' });

        if (process.env.NODE_ENV !== 'production') {
            setTimeout(async () => {
                const newBal = await creditBalance(normalizedPhone, parsedAmount);
                io.to(`phone:${normalizedPhone}`).emit('balance_update', {
                    balance: parseFloat(newBal).toFixed(2)
                });
            }, 5000);
        }

    } catch (err) {
        audit('deposit_error', { phone: normalizedPhone, error: err.message });
        res.status(500).json({ error: 'Deposit failed. Please try again.' });
    }
});

// ─── DEPOSIT WEBHOOK ─────────────────────────────────────────────────────
app.post('/intasend/webhook', async (req, res) => {
    const { invoice_id, state, net_amount, account } = req.body;
    if (state !== 'COMPLETE') return res.send('OK');

    const pendingRaw = await redis.get(`deposit:${invoice_id}`);
    let phone, amount;

    if (pendingRaw) {
        ({ phone, amount } = JSON.parse(pendingRaw));
        await redis.del(`deposit:${invoice_id}`);
    } else {
        phone = normalizePhone(account) || normalizePhone(req.body.phone_number);
        amount = net_amount;
    }

    if (!phone || !amount) return res.status(400).send('Missing data');

    const newBal = await creditBalance(phone, amount);
    audit('deposit_completed', { phone, amount });
    io.to(`phone:${phone}`).emit('balance_update', { balance: parseFloat(newBal).toFixed(2) });
    res.send('OK');
});

// ─── WITHDRAWAL ───────────────────────────────────────────────────────────
app.post('/mpesa/withdraw', withdrawLimiter, async (req, res) => {
    const { phone, amount } = req.body;

    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) return res.status(400).json({ error: 'Invalid phone number.' });

    const parsedAmount = validateAmount(amount);
    if (!parsedAmount || parsedAmount < 10) {
        return res.status(400).json({ error: 'Minimum withdrawal is KES 10.' });
    }

    if (process.env.DEMO_MODE === 'true') {
        return res.status(403).json({ error: 'Withdrawals disabled in demo mode. This is play money only!' });
    }

    const totalDeduct = parsedAmount + WITHDRAW_FEE;
    const deducted = await deductBalance(normalizedPhone, totalDeduct);
    if (!deducted) {
        return res.status(400).json({
            error: `Insufficient balance. You need KES ${totalDeduct} (KES ${parsedAmount} + KES ${WITHDRAW_FEE} fee).`
        });
    }

    try {
        const payouts = intasend.payouts();
        const resp = await payouts.mpesa({
            currency: 'KES',
            requires_approval: 'NO',
            transactions: [{
                name: 'Player',
                account: normalizedPhone,
                amount: String(parsedAmount),
                narrative: 'TicTacCash Withdrawal',
            }]
        });

        audit('withdrawal_initiated', { phone: normalizedPhone, amount: parsedAmount });

        if (resp?.tracking_id) {
            await redis.set(
                `withdrawal:${resp.tracking_id}`,
                JSON.stringify({ phone: normalizedPhone, amount: parsedAmount }),
                { EX: 3600 }
            );
        }

        res.json({ msg: `Withdrawal of KES ${parsedAmount} initiated. You'll receive M-Pesa shortly. (KES ${WITHDRAW_FEE} fee applied)` });

    } catch (err) {
        await creditBalance(normalizedPhone, totalDeduct);
        audit('withdrawal_error', { phone: normalizedPhone, error: err.message });
        res.status(500).json({ error: 'Withdrawal failed. Your balance has been refunded.' });
    }
});

// ─── WITHDRAWAL WEBHOOK ───────────────────────────────────────────────────
app.post('/intasend/webhook/payouts', async (req, res) => {
    const { tracking_id, status, failed_reason } = req.body;

    const pendingRaw = await redis.get(`withdrawal:${tracking_id}`);
    if (!pendingRaw) return res.send('OK');

    const { phone, amount } = JSON.parse(pendingRaw);
    await redis.del(`withdrawal:${tracking_id}`);

    if (status === 'TP' || status === 'Completed') {
        audit('withdrawal_completed', { phone, amount });
        const newBal = await getBalance(phone);
        io.to(`phone:${phone}`).emit('balance_update', { balance: newBal.toFixed(2) });
        io.to(`phone:${phone}`).emit('withdrawal_success', { amount });
    } else {
        audit('withdrawal_failed', { phone, amount, reason: failed_reason });
        const newBal = await creditBalance(phone, amount + WITHDRAW_FEE);
        io.to(`phone:${phone}`).emit('balance_update', { balance: parseFloat(newBal).toFixed(2) });
        io.to(`phone:${phone}`).emit('withdrawal_failed', { reason: failed_reason || 'Payment failed' });
    }

    res.send('OK');
});

// ─── GLOBAL ERROR HANDLER ─────────────────────────────────────────────────
app.use((err, req, res, next) => {
    audit('server_error', { path: req.path, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
});

// ─── START ────────────────────────────────────────────────────────────────
async function start() {
    await redis.connect();
    await redisPub.connect();
    await redisSub.connect();

    // Attach Redis adapter for multi-instance support
    io.adapter(createAdapter(redisPub, redisSub));

    await redis.del('matchmaking_queue');

    io.on('connection', async (socket) => {
        await broadcastOnlineCount();

        // ── AUTH ──────────────────────────────────────────────────────────
        socket.on('auth', async ({ phone }) => {
            const normalizedPhone = normalizePhone(phone);
            if (!normalizedPhone) {
                audit('auth_rejected', { phone, reason: 'invalid_format' });
                return socket.emit('error_msg', 'Invalid phone number. Use format: 07XXXXXXXX or 2547XXXXXXXX');
            }

            socket.phone = normalizedPhone;
            socket.join(`phone:${normalizedPhone}`);

            const hasPlayed = await redis.get(`user:${normalizedPhone}:demo_claimed`);
            if (!hasPlayed) {
                await creditBalance(normalizedPhone, DEMO_BONUS);
                await redis.set(`user:${normalizedPhone}:demo_claimed`, '1');
                audit('demo_bonus_credited', { phone: normalizedPhone, amount: DEMO_BONUS });
                socket.emit('demo_bonus', { amount: DEMO_BONUS });
            } else {
                // Top up if balance is too low to play (helps returning testers)
                const currentBal = await getBalance(normalizedPhone);
                if (currentBal < ENTRY_FEE) {
                    await creditBalance(normalizedPhone, DEMO_BONUS);
                    audit('demo_topup', { phone: normalizedPhone, amount: DEMO_BONUS });
                    socket.emit('demo_bonus', { amount: DEMO_BONUS });
                }
            }

            const bal = await getBalance(normalizedPhone);
            audit('auth', { phone: normalizedPhone });
            socket.emit('auth_success', { balance: bal.toFixed(2) });
            await broadcastOnlineCount();
        });

        // ── FIND MATCH ────────────────────────────────────────────────────
        socket.on('find_match', async () => {
            if (!socket.phone) return socket.emit('error_msg', 'Not authenticated.');
            if (socket.searching) return; // prevent double click
            socket.searching = true; // lock immediately to prevent race condition

            const deducted = await deductBalance(socket.phone, ENTRY_FEE);
            if (!deducted) {
                socket.searching = false;
                return socket.emit('error_msg', `Insufficient balance. Min KES ${ENTRY_FEE} required.`);
            }
            const newBal = await getBalance(socket.phone);
            socket.emit('balance_update', { balance: newBal.toFixed(2) });

            // Keep popping until we find a live opponent or the queue is empty
            let matched = false;
            while (true) {
                const queueEntry = await redis.lPop('matchmaking_queue');
                if (!queueEntry) break;

                const [opponentPhone, opponentSocketId] = queueEntry.split('::');

                // Skip stale entries (same player re-queued, or disconnected opponent)
                if (opponentPhone === socket.phone || opponentSocketId === socket.id) {
                    await creditBalance(opponentPhone, ENTRY_FEE);
                    continue;
                }

                const opponentSocket = io.sockets.sockets.get(opponentSocketId);
                if (!opponentSocket || !opponentSocket.searching) {
                    // Opponent gone or cancelled — refund them and keep looking
                    await creditBalance(opponentPhone, ENTRY_FEE);
                    continue;
                }

                // Valid match found
                opponentSocket.searching = false;
                socket.searching = false;

                const gameId = `game_${crypto.randomUUID()}`;
                socket.join(gameId);
                opponentSocket.join(gameId);

                const game = {
                    board: Array(9).fill(null),
                    players: { X: socket.phone, O: opponentPhone },
                    sockets: { X: socket.id, O: opponentSocketId },
                    currentTurn: 'X',
                };

                await saveGame(gameId, game);
                audit('game_started', { gameId, playerX: socket.phone, playerO: opponentPhone });

                io.to(gameId).emit('match_found', {
                    gameId,
                    playerX: socket.id,
                    playerO: opponentSocketId,
                });
                await broadcastOnlineCount();
                matched = true;
                break;
            }

            if (!matched) {
                await redis.rPush('matchmaking_queue', `${socket.phone}::${socket.id}`);
                socket.emit('waiting', {});
                await broadcastOnlineCount();
            }
        });

        // ── CANCEL SEARCH ─────────────────────────────────────────────────
        socket.on('cancel_search', async () => {
            if (!socket.phone || !socket.searching) return;

            const queue = await redis.lRange('matchmaking_queue', 0, -1);
            for (const entry of queue) {
                if (entry.startsWith(`${socket.phone}::`) || entry.endsWith(`::${socket.id}`)) {
                    await redis.lRem('matchmaking_queue', 0, entry);
                    await creditBalance(socket.phone, ENTRY_FEE);
                }
            }

            socket.searching = false;
            const bal = await getBalance(socket.phone);
            socket.emit('balance_update', { balance: bal.toFixed(2) });
            socket.emit('search_cancelled', {});
            audit('search_cancelled', { phone: socket.phone });
            await broadcastOnlineCount();
        });

        // ── MAKE MOVE ─────────────────────────────────────────────────────
        socket.on('make_move', async ({ gameId, index }) => {
            const game = await getGame(gameId);
            if (!game) return socket.emit('error_msg', 'Game not found.');

            const mySymbol = game.sockets.X === socket.id ? 'X' : game.sockets.O === socket.id ? 'O' : null;
            if (!mySymbol) return socket.emit('error_msg', 'You are not in this game.');
            if (game.currentTurn !== mySymbol) return socket.emit('error_msg', 'Not your turn.');
            if (typeof index !== 'number' || index < 0 || index > 8) return socket.emit('error_msg', 'Invalid move.');
            if (game.board[index]) return socket.emit('error_msg', 'Cell already taken.');

            game.board[index] = mySymbol;
            game.currentTurn = mySymbol === 'X' ? 'O' : 'X';
            await saveGame(gameId, game);

            io.to(gameId).emit('move_made', { index, symbol: mySymbol, nextTurn: game.currentTurn });

            const result = checkWinner(game.board);
            if (result) {
                if (result === 'DRAW') {
                    await Promise.all([
                        creditBalance(game.players.X, DRAW_REFUND),
                        creditBalance(game.players.O, DRAW_REFUND),
                    ]);
                    const [balX, balO] = await Promise.all([
                        getBalance(game.players.X),
                        getBalance(game.players.O),
                    ]);
                    const socketX = io.sockets.sockets.get(game.sockets.X);
                    const socketO = io.sockets.sockets.get(game.sockets.O);
                    if (socketX) socketX.emit('balance_update', { balance: balX.toFixed(2) });
                    if (socketO) socketO.emit('balance_update', { balance: balO.toFixed(2) });
                    audit('game_draw', { gameId });
                    io.to(gameId).emit('game_finished', { result: 'DRAW', winner: null, winnerSocketId: null, refund: DRAW_REFUND });
                } else {
                    const winnerPhone = game.players[result];
                    const winnerSocketId = game.sockets[result];
                    await creditBalance(winnerPhone, WIN_PRIZE);
                    const newBal = await getBalance(winnerPhone);
                    const winnerSocket = io.sockets.sockets.get(winnerSocketId);
                    if (winnerSocket) winnerSocket.emit('balance_update', { balance: newBal.toFixed(2) });
                    audit('game_won', { gameId, winner: winnerPhone, prize: WIN_PRIZE });
                    io.to(gameId).emit('game_finished', { result: 'WIN', winner: result, winnerSocketId, prize: WIN_PRIZE });
                }
                await deleteGame(gameId);
                await broadcastOnlineCount();
            }
        });

        // ── DISCONNECT ────────────────────────────────────────────────────
        socket.on('disconnect', async () => {
            if (socket.phone) {
                // Remove from queue and refund if searching
                if (socket.searching) {
                    const queue = await redis.lRange('matchmaking_queue', 0, -1);
                    for (const entry of queue) {
                        if (entry.startsWith(`${socket.phone}::`) || entry.endsWith(`::${socket.id}`)) {
                            await redis.lRem('matchmaking_queue', 0, entry);
                            await creditBalance(socket.phone, ENTRY_FEE);
                        }
                    }
                }

                // Handle mid-game disconnect
                const gameKeys = await redis.keys('game:*');
                for (const key of gameKeys) {
                    const raw = await redis.get(key);
                    if (!raw) continue;
                    const game = JSON.parse(raw);
                    if (game.sockets.X === socket.id || game.sockets.O === socket.id) {
                        const gameId = key.replace('game:', '');
                        const mySymbol = game.sockets.X === socket.id ? 'X' : 'O';
                        const opponentSymbol = mySymbol === 'X' ? 'O' : 'X';
                        const opponentPhone = game.players[opponentSymbol];
                        const opponentSocketId = game.sockets[opponentSymbol];

                        await creditBalance(opponentPhone, WIN_PRIZE);
                        const newBal = await getBalance(opponentPhone);
                        const opponentSocket = io.sockets.sockets.get(opponentSocketId);
                        if (opponentSocket) {
                            opponentSocket.searching = false;
                            opponentSocket.emit('balance_update', { balance: newBal.toFixed(2) });
                            opponentSocket.emit('game_finished', {
                                result: 'FORFEIT',
                                winner: opponentSymbol,
                                winnerSocketId: opponentSocketId,
                                prize: WIN_PRIZE,
                            });
                        }
                        audit('game_forfeit', { gameId, winner: opponentPhone });
                        await deleteGame(gameId);
                    }
                }
            }
            await broadcastOnlineCount();
        });

        // ── GET BALANCE ───────────────────────────────────────────────────
        socket.on('get_balance', async () => {
            if (!socket.phone) return;
            const bal = await getBalance(socket.phone);
            socket.emit('balance_update', { balance: bal.toFixed(2) });
        });
    });

    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => console.log(`🚀 TicTac Cash: http://localhost:${PORT}`));
}

const checkWinner = (board) => {
    for (const [a, b, c] of WIN_COMBOS) {
        if (board[a] && board[a] === board[b] && board[a] === board[c]) return board[a];
    }
    return board.every(Boolean) ? 'DRAW' : null;
};

start();