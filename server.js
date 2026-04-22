require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { createClient } = require('redis');
const IntaSend = require('intasend-node');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const redis = createClient({ url: process.env.REDIS_URL || 'redis://127.0.0.1:6380' });

// ─── SECURITY HEADERS (fixes all 7 failing checks) ───────────────────────
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            connectSrc: ["'self'", "wss:", "ws:"],
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
    windowMs: 60 * 1000,        // 1 minute
    max: 5,                      // 5 deposit attempts per minute
    message: { error: 'Too many deposit attempts. Please wait a minute.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const withdrawLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 3,                      // 3 withdrawal attempts per minute
    message: { error: 'Too many withdrawal attempts. Please wait a minute.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max: 20,                     // 20 auth attempts per 15 min
    message: { error: 'Too many requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// ─── CONSTANTS ────────────────────────────────────────────────────────────
const ENTRY_FEE = 50;
const WIN_PRIZE = 85;           // 100 pot - 15 rake
const DRAW_REFUND = 50;         // Full refund on draw
const WITHDRAW_FEE = 10;        // IntaSend B2C charge paid by player
const DEMO_BONUS = 1000;        // Free demo money on first login
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
    if (/^2547\d{8}$/.test(cleaned)) return cleaned;
    if (/^07\d{8}$/.test(cleaned)) return '254' + cleaned.slice(1);
    if (/^7\d{8}$/.test(cleaned)) return '254' + cleaned;
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

// ─── AUDIT LOGGER ─────────────────────────────────────────────────────────
const audit = (event, data) => {
    console.log(JSON.stringify({
        timestamp: new Date().toISOString(),
        event,
        ...data,
    }));
};

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

// ─── SERVER-SIDE GAME STATE ───────────────────────────────────────────────
const games = new Map();

const checkWinner = (board) => {
    for (const [a, b, c] of WIN_COMBOS) {
        if (board[a] && board[a] === board[b] && board[a] === board[c]) return board[a];
    }
    return board.every(Boolean) ? 'DRAW' : null;
};

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

    // Block deposits in demo mode
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

        audit('deposit_initiated', { phone: normalizedPhone, amount: parsedAmount, invoice: resp.invoice?.invoice_id });

        await redis.set(
            `deposit:${resp.invoice?.invoice_id}`,
            JSON.stringify({ phone: normalizedPhone, amount: parsedAmount }),
            { EX: 3600 }
        );

        res.json({ msg: 'STK Prompt Sent! Check your phone.' });

        // ── SANDBOX ONLY: auto-credit after 5 seconds ──
        if (process.env.NODE_ENV !== 'production') {
            setTimeout(async () => {
                const newBal = await creditBalance(normalizedPhone, parsedAmount);
                audit('deposit_autocredited', { phone: normalizedPhone, amount: parsedAmount, newBalance: newBal });
                io.to(`phone:${normalizedPhone}`).emit('balance_update', {
                    balance: parseFloat(newBal).toFixed(2)
                });
            }, 5000);
        }

    } catch (err) {
        audit('deposit_error', { phone: normalizedPhone, amount: parsedAmount, error: err.message });
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

    if (!phone || !amount) {
        audit('webhook_error', { invoice_id, reason: 'missing phone or amount' });
        return res.status(400).send('Missing data');
    }

    const newBal = await creditBalance(phone, amount);
    audit('deposit_completed', { phone, amount, newBalance: newBal });
    io.to(`phone:${phone}`).emit('balance_update', {
        balance: parseFloat(newBal).toFixed(2)
    });

    res.send('OK');
});

// ─── WITHDRAWAL: B2C ─────────────────────────────────────────────────────
app.post('/mpesa/withdraw', withdrawLimiter, async (req, res) => {
    const { phone, amount } = req.body;

    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) {
        return res.status(400).json({ error: 'Invalid phone number.' });
    }

    const parsedAmount = validateAmount(amount);
    if (!parsedAmount || parsedAmount < 10) {
        return res.status(400).json({ error: 'Minimum withdrawal is KES 10.' });
    }

    // Block withdrawals in demo mode
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

        audit('withdrawal_initiated', { phone: normalizedPhone, amount: parsedAmount, tracking: resp?.tracking_id });

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
        audit('withdrawal_error', { phone: normalizedPhone, amount: parsedAmount, error: err.message });
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

// ─── GLOBAL ERROR HANDLER (no stack traces in production) ─────────────────
app.use((err, req, res, next) => {
    audit('server_error', { path: req.path, error: err.message });
    res.status(500).json({ error: 'Internal server error' });
});

// ─── SOCKET.IO ────────────────────────────────────────────────────────────
async function start() {
    await redis.connect();
    await redis.del('matchmaking_queue');

    io.on('connection', (socket) => {

        // ── AUTH ──────────────────────────────────────────────────────────
        socket.on('auth', async ({ phone }) => {
            const normalizedPhone = normalizePhone(phone);
            if (!normalizedPhone) return socket.emit('error_msg', 'Invalid phone number.');

            socket.phone = normalizedPhone;
            socket.join(`phone:${normalizedPhone}`);

            // ── DEMO BONUS: give KES 1,000 to first-time users ──
            const hasPlayed = await redis.get(`user:${normalizedPhone}:demo_claimed`);
            if (!hasPlayed) {
                await creditBalance(normalizedPhone, DEMO_BONUS);
                await redis.set(`user:${normalizedPhone}:demo_claimed`, '1');
                audit('demo_bonus_credited', { phone: normalizedPhone, amount: DEMO_BONUS });
                socket.emit('info_msg', `🎉 Welcome! KES ${DEMO_BONUS} demo balance added to your account.`);
            }

            const bal = await getBalance(normalizedPhone);
            audit('auth', { phone: normalizedPhone });
            socket.emit('auth_success', { balance: bal.toFixed(2) });
        });

        // ── FIND MATCH ────────────────────────────────────────────────────
        socket.on('find_match', async () => {
            if (!socket.phone) return socket.emit('error_msg', 'Not authenticated.');

            const deducted = await deductBalance(socket.phone, ENTRY_FEE);
            if (!deducted) {
                return socket.emit('error_msg', `Insufficient balance. Min KES ${ENTRY_FEE} required.`);
            }

            const newBal = await getBalance(socket.phone);
            socket.emit('balance_update', { balance: newBal.toFixed(2) });

            const queueEntry = await redis.lPop('matchmaking_queue');

            if (queueEntry) {
                const [opponentPhone, opponentSocketId] = queueEntry.split('::');
                const opponentSocket = io.sockets.sockets.get(opponentSocketId);

                if (!opponentSocket) {
                    await creditBalance(opponentPhone, ENTRY_FEE);
                    await redis.rPush('matchmaking_queue', `${socket.phone}::${socket.id}`);
                    socket.emit('info_msg', 'Searching for opponent...');
                    return;
                }

                const gameId = `game_${crypto.randomUUID()}`;
                socket.join(gameId);
                opponentSocket.join(gameId);

                games.set(gameId, {
                    board: Array(9).fill(null),
                    players: { X: socket.phone, O: opponentPhone },
                    sockets: { X: socket.id, O: opponentSocketId },
                    currentTurn: 'X',
                });

                audit('game_started', { gameId, playerX: socket.phone, playerO: opponentPhone });

                io.to(gameId).emit('match_found', {
                    gameId,
                    playerX: socket.id,
                    playerO: opponentSocketId,
                });
            } else {
                await redis.rPush('matchmaking_queue', `${socket.phone}::${socket.id}`);
                socket.emit('info_msg', 'Searching for opponent...');
            }
        });

        // ── MAKE MOVE ─────────────────────────────────────────────────────
        socket.on('make_move', async ({ gameId, index }) => {
            const game = games.get(gameId);
            if (!game) return socket.emit('error_msg', 'Game not found.');

            const mySymbol = game.sockets.X === socket.id ? 'X' : game.sockets.O === socket.id ? 'O' : null;
            if (!mySymbol) return socket.emit('error_msg', 'You are not in this game.');
            if (game.currentTurn !== mySymbol) return socket.emit('error_msg', 'Not your turn.');
            if (typeof index !== 'number' || index < 0 || index > 8) return socket.emit('error_msg', 'Invalid move.');
            if (game.board[index]) return socket.emit('error_msg', 'Cell already taken.');

            game.board[index] = mySymbol;
            game.currentTurn = mySymbol === 'X' ? 'O' : 'X';

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
                    io.to(gameId).emit('game_finished', {
                        result: 'DRAW',
                        winner: null,
                        winnerSocketId: null,
                        refund: DRAW_REFUND,
                    });
                } else {
                    const winnerPhone = game.players[result];
                    const winnerSocketId = game.sockets[result];
                    await creditBalance(winnerPhone, WIN_PRIZE);
                    const newBal = await getBalance(winnerPhone);
                    const winnerSocket = io.sockets.sockets.get(winnerSocketId);
                    if (winnerSocket) winnerSocket.emit('balance_update', { balance: newBal.toFixed(2) });
                    audit('game_won', { gameId, winner: winnerPhone, prize: WIN_PRIZE });
                    io.to(gameId).emit('game_finished', {
                        result: 'WIN',
                        winner: result,
                        winnerSocketId,
                        prize: WIN_PRIZE,
                    });
                }
                games.delete(gameId);
            }
        });

        // ── DISCONNECT ────────────────────────────────────────────────────
        socket.on('disconnect', async () => {
            if (socket.phone) {
                const queue = await redis.lRange('matchmaking_queue', 0, -1);
                for (const entry of queue) {
                    if (entry.startsWith(`${socket.phone}::`) || entry.endsWith(`::${socket.id}`)) {
                        await redis.lRem('matchmaking_queue', 0, entry);
                        await creditBalance(socket.phone, ENTRY_FEE);
                    }
                }

                for (const [gameId, game] of games.entries()) {
                    if (game.sockets.X === socket.id || game.sockets.O === socket.id) {
                        const mySymbol = game.sockets.X === socket.id ? 'X' : 'O';
                        const opponentSymbol = mySymbol === 'X' ? 'O' : 'X';
                        const opponentPhone = game.players[opponentSymbol];
                        const opponentSocketId = game.sockets[opponentSymbol];

                        await creditBalance(opponentPhone, WIN_PRIZE);
                        const newBal = await getBalance(opponentPhone);
                        const opponentSocket = io.sockets.sockets.get(opponentSocketId);
                        if (opponentSocket) {
                            opponentSocket.emit('balance_update', { balance: newBal.toFixed(2) });
                            opponentSocket.emit('game_finished', {
                                result: 'FORFEIT',
                                winner: opponentSymbol,
                                winnerSocketId: opponentSocketId,
                                prize: WIN_PRIZE,
                            });
                        }
                        audit('game_forfeit', { gameId, winner: opponentPhone });
                        games.delete(gameId);
                    }
                }
            }
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

start();