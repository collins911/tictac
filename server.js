require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { createClient } = require('redis');
const IntaSend = require('intasend-node');
const path = require('path');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const redis = createClient({ url: process.env.REDIS_URL || 'redis://127.0.0.1:6380' });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const ENTRY_FEE = 50;       // Each player pays KES 50
const RAKE = 15;            // Your profit per game (100 pot - 85 prize)
const WITHDRAW_FEE = 10;    // IntaSend B2C charge, paid by player on withdrawal
const WIN_PRIZE = 85;       // 100 pot - 15 rake = 85 to winner
const DRAW_REFUND = 50;     // Full refund on draw, no withdraw fee charged
const WIN_COMBOS = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];

// ─── INTASEND CLIENT ─────────────────────────────────────────────────────

const intasend = new IntaSend(
    process.env.INTASEND_PUBLISHABLE_KEY,
    process.env.INTASEND_SECRET_KEY,
    process.env.NODE_ENV !== 'production'
);

// ─── HELPERS ────────────────────────────────────────────────────────────────

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

// ─── SERVER-SIDE GAME STATE ───────────────────────────────────────────────

const games = new Map();

const checkWinner = (board) => {
    for (const [a, b, c] of WIN_COMBOS) {
        if (board[a] && board[a] === board[b] && board[a] === board[c]) return board[a];
    }
    return board.every(Boolean) ? 'DRAW' : null;
};

// ─── DEPOSIT: STK PUSH ────────────────────────────────────────────────────

app.post('/mpesa/deposit', async (req, res) => {
    const { phone, amount } = req.body;

    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) return res.status(400).json({ error: 'Invalid phone number format. Use 2547XXXXXXXX.' });

    const parsedAmount = parseInt(amount, 10);
    if (isNaN(parsedAmount) || parsedAmount < 1 || parsedAmount > 100000) {
        return res.status(400).json({ error: 'Amount must be between KES 1 and KES 100,000.' });
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

        console.log('STK Push success:', resp);

        await redis.set(
            `deposit:${resp.invoice?.invoice_id}`,
            JSON.stringify({ phone: normalizedPhone, amount: parsedAmount }),
            { EX: 3600 }
        );

        res.json({ msg: 'STK Prompt Sent! Check your phone.' });

        // ── SANDBOX ONLY: auto-credit after 5 seconds ──
        if (process.env.NODE_ENV !== 'production') {
            console.log(`[Sandbox] Will auto-credit KES ${parsedAmount} to ${normalizedPhone} in 5s...`);
            setTimeout(async () => {
                console.log(`[Sandbox] Auto-crediting KES ${parsedAmount} to ${normalizedPhone}`);
                const newBal = await creditBalance(normalizedPhone, parsedAmount);
                console.log(`[Sandbox] New balance: ${newBal}`);
                io.to(`phone:${normalizedPhone}`).emit('balance_update', {
                    balance: parseFloat(newBal).toFixed(2)
                });
            }, 5000);
        }

    } catch (err) {
        console.error('STK Push Error:', err);
        res.status(500).json({ error: 'Deposit failed. Please try again.', detail: err.message });
    }
});

// ─── DEPOSIT WEBHOOK ─────────────────────────────────────────────────────

app.post('/intasend/webhook', async (req, res) => {
    const { invoice_id, state, net_amount, account } = req.body;
    console.log('IntaSend webhook:', req.body);

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
        console.error('Webhook: missing phone or amount', req.body);
        return res.status(400).send('Missing data');
    }

    console.log(`Webhook: crediting KES ${amount} to ${phone}`);
    const newBal = await creditBalance(phone, amount);
    io.to(`phone:${phone}`).emit('balance_update', {
        balance: parseFloat(newBal).toFixed(2)
    });

    res.send('OK');
});

// ─── WITHDRAWAL: B2C ─────────────────────────────────────────────────────

app.post('/mpesa/withdraw', async (req, res) => {
    const { phone, amount } = req.body;

    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) return res.status(400).json({ error: 'Invalid phone number.' });

    const parsedAmount = parseInt(amount, 10);
    if (isNaN(parsedAmount) || parsedAmount < 10) {
        return res.status(400).json({ error: 'Minimum withdrawal is KES 10.' });
    }

    // Deduct amount + KES 10 withdrawal fee from balance
    const totalDeduct = parsedAmount + WITHDRAW_FEE;
    const deducted = await deductBalance(normalizedPhone, totalDeduct);
    if (!deducted) {
        return res.status(400).json({
            error: `Insufficient balance. You need KES ${totalDeduct} (KES ${parsedAmount} + KES ${WITHDRAW_FEE} withdrawal fee).`
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

        console.log('B2C initiated:', resp);

        if (resp?.tracking_id) {
            await redis.set(
                `withdrawal:${resp.tracking_id}`,
                JSON.stringify({ phone: normalizedPhone, amount: parsedAmount }),
                { EX: 3600 }
            );
        }

        res.json({ msg: `Withdrawal of KES ${parsedAmount} initiated. You'll receive M-Pesa shortly. (KES ${WITHDRAW_FEE} fee applied)` });

    } catch (err) {
        // Refund full amount including fee on failure
        await creditBalance(normalizedPhone, totalDeduct);
        console.error('Withdrawal Error:', err);
        res.status(500).json({
            error: 'Withdrawal failed. Your balance has been refunded.',
            detail: err.message
        });
    }
});

// ─── WITHDRAWAL WEBHOOK ───────────────────────────────────────────────────

app.post('/intasend/webhook/payouts', async (req, res) => {
    const { tracking_id, status, failed_reason } = req.body;
    console.log('Payout webhook:', req.body);

    const pendingRaw = await redis.get(`withdrawal:${tracking_id}`);
    if (!pendingRaw) return res.send('OK');

    const { phone, amount } = JSON.parse(pendingRaw);
    await redis.del(`withdrawal:${tracking_id}`);

    if (status === 'TP' || status === 'Completed') {
        console.log(`Withdrawal success for ${phone}: KES ${amount}`);
        const newBal = await getBalance(phone);
        io.to(`phone:${phone}`).emit('balance_update', { balance: newBal.toFixed(2) });
        io.to(`phone:${phone}`).emit('withdrawal_success', { amount });
    } else {
        // Refund amount + fee on failure
        console.log(`Withdrawal failed for ${phone}, refunding KES ${amount + WITHDRAW_FEE}. Reason: ${failed_reason}`);
        const newBal = await creditBalance(phone, amount + WITHDRAW_FEE);
        io.to(`phone:${phone}`).emit('balance_update', { balance: parseFloat(newBal).toFixed(2) });
        io.to(`phone:${phone}`).emit('withdrawal_failed', { reason: failed_reason || 'Payment failed' });
    }

    res.send('OK');
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

            const bal = await getBalance(normalizedPhone);
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
                    // Full refund on draw — no withdrawal fee charged
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
                    io.to(gameId).emit('game_finished', {
                        result: 'DRAW',
                        winner: null,
                        winnerSocketId: null,
                        refund: DRAW_REFUND,
                    });
                } else {
                    // Winner gets WIN_PRIZE
                    const winnerPhone = game.players[result];
                    const winnerSocketId = game.sockets[result];
                    await creditBalance(winnerPhone, WIN_PRIZE);
                    const newBal = await getBalance(winnerPhone);
                    const winnerSocket = io.sockets.sockets.get(winnerSocketId);
                    if (winnerSocket) winnerSocket.emit('balance_update', { balance: newBal.toFixed(2) });
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