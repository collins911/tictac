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

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { 
    transports: ['websocket', 'polling'],
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// ─── REDIS (balances and PINs) ────────────────────────────────────────────
const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error',   e => console.error('Redis error:', e.message));
redis.on('connect', () => console.log('Redis connected'));

// ─── IN-MEMORY STATE ──────────────────────────────────────────────────────
let   waitingSocket = null;          // single socket waiting for opponent
const games         = new Map();     // gameId -> game object
const balances      = new Map();     // phone  -> balance (fallback if Redis down)
const privateRooms  = new Map();     // roomCode -> { creator, createdAt, players }
const userPins      = new Map();     // phone  -> hashed PIN (fallback)

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
const authLimiter     = rateLimit({ windowMs: 60000, max: 10, message: { error: 'Too many login attempts.' } });

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

const validatePin = (pin) => {
    return /^\d{4}$/.test(pin);
};

// Generate a short room code
const generateRoomCode = () => {
    return crypto.randomBytes(3).toString('hex').toUpperCase();
};

// ─── PIN MANAGEMENT ───────────────────────────────────────────────────────
const hashPin = async (pin) => {
    return await bcrypt.hash(pin, 10);
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
    console.log(`📊 Online: ${online}, Searching: ${searching}`);
    io.emit('online_count', { online, searching });
};

// ─── PERIODIC CLEANUP ─────────────────────────────────────────────────────
setInterval(() => {
    if (waitingSocket) {
        const stillConnected = io.sockets.sockets.has(waitingSocket.id);
        if (!stillConnected) {
            console.log('🧹 Cleaning up stale waiting socket');
            waitingSocket = null;
            broadcastOnlineCount();
        } else if (!waitingSocket.searching) {
            console.log('🧹 Cleaning up waiting socket that stopped searching');
            waitingSocket = null;
            broadcastOnlineCount();
        }
    }
    
    // Clean up old private rooms (older than 1 hour)
    const now = Date.now();
    for (const [code, room] of privateRooms.entries()) {
        if (now - room.createdAt > 3600000) { // 1 hour
            privateRooms.delete(code);
            console.log(`🧹 Cleaned up old private room: ${code}`);
        }
    }
}, 5000);

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now(), redis: redis.isReady }));

// ─── GET ROOM INFO ────────────────────────────────────────────────────────
app.get('/api/room/:code', (req, res) => {
    const { code } = req.params;
    const room = privateRooms.get(code.toUpperCase());
    if (room) {
        res.json({ 
            exists: true, 
            creator: room.creator,
            playerJoined: !!room.playerSocket 
        });
    } else {
        res.json({ exists: false });
    }
});

// ─── CHECK USER EXISTS ────────────────────────────────────────────────────
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
    socket.searching = false;
    socket.currentRoom = null;
    socket.authenticated = false;
    console.log(`🔌 New connection: ${socket.id}`);
    broadcastOnlineCount();

    // ─── CHECK IF USER EXISTS ─────────────────────────────────────────────
    socket.on('check_user', async ({ phone }) => {
        const normalizedPhone = normalizePhone(phone);
        if (!normalizedPhone) {
            return socket.emit('error_msg', 'Invalid phone number.');
        }
        const exists = await userExists(normalizedPhone);
        socket.emit('user_check_result', { exists, phone: normalizedPhone });
    });

    // ─── REGISTER NEW USER ────────────────────────────────────────────────
    socket.on('register', async ({ phone, pin }) => {
        const normalizedPhone = normalizePhone(phone);
        if (!normalizedPhone) {
            return socket.emit('error_msg', 'Invalid phone number.');
        }
        if (!validatePin(pin)) {
            return socket.emit('error_msg', 'PIN must be 4 digits.');
        }
        
        const exists = await userExists(normalizedPhone);
        if (exists) {
            return socket.emit('error_msg', 'User already exists. Please login.');
        }
        
        await setUserPin(normalizedPhone, pin);
        
        // Give demo bonus
        await creditBalance(normalizedPhone, DEMO_BONUS);
        await setDemoClaimed(normalizedPhone);
        
        audit('user_registered', { phone: normalizedPhone });
        socket.emit('registration_success', { phone: normalizedPhone });
        console.log(`✅ New user registered: ${normalizedPhone}`);
    });

    // ─── AUTHENTICATE (LOGIN) ─────────────────────────────────────────────
    socket.on('auth', async ({ phone, pin }) => {
        console.log(`🔐 Auth attempt for phone: ${phone}`);
        const normalizedPhone = normalizePhone(phone);
        if (!normalizedPhone) {
            console.log(`❌ Invalid phone number: ${phone}`);
            return socket.emit('error_msg', 'Invalid phone number.');
        }
        if (!validatePin(pin)) {
            return socket.emit('error_msg', 'PIN must be 4 digits.');
        }
        
        const storedPin = await getUserPin(normalizedPhone);
        if (!storedPin) {
            return socket.emit('error_msg', 'User not found. Please register.');
        }
        
        const pinValid = await verifyPin(pin, storedPin);
        if (!pinValid) {
            audit('auth_failed', { phone: normalizedPhone, reason: 'Invalid PIN' });
            return socket.emit('error_msg', 'Invalid PIN.');
        }
        
        socket.phone = normalizedPhone;
        socket.authenticated = true;
        socket.join(`phone:${normalizedPhone}`);

        const bal = await getBalance(normalizedPhone);
        
        // Check if demo bonus needed (low balance)
        if (bal < ENTRY_FEE) {
            await creditBalance(normalizedPhone, DEMO_BONUS);
            audit('demo_topup', { phone: normalizedPhone });
            socket.emit('demo_bonus', { amount: DEMO_BONUS });
        }
        
        const updatedBal = await getBalance(normalizedPhone);
        audit('auth_success', { phone: normalizedPhone, balance: updatedBal });
        socket.emit('auth_success', { balance: updatedBal.toFixed(2) });
        broadcastOnlineCount();
        console.log(`✅ Auth success: ${normalizedPhone} - Balance: ${updatedBal}`);
    });

    // ─── CHANGE PIN ───────────────────────────────────────────────────────
    socket.on('change_pin', async ({ oldPin, newPin }) => {
        if (!socket.authenticated || !socket.phone) {
            return socket.emit('error_msg', 'Not authenticated.');
        }
        if (!validatePin(oldPin) || !validatePin(newPin)) {
            return socket.emit('error_msg', 'PIN must be 4 digits.');
        }
        
        const storedPin = await getUserPin(socket.phone);
        const pinValid = await verifyPin(oldPin, storedPin);
        if (!pinValid) {
            return socket.emit('error_msg', 'Current PIN is incorrect.');
        }
        
        await setUserPin(socket.phone, newPin);
        audit('pin_changed', { phone: socket.phone });
        socket.emit('pin_changed', {});
        console.log(`🔐 PIN changed for: ${socket.phone}`);
    });

    // ─── CREATE PRIVATE ROOM ───────────────────────────────────────────────
    socket.on('create_private_room', async () => {
        if (!socket.authenticated || !socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (socket.searching) return socket.emit('error_msg', 'Already searching.');
        if (socket.currentRoom) return socket.emit('error_msg', 'Already in a room.');
        
        const deducted = await deductBalance(socket.phone, ENTRY_FEE);
        if (!deducted) {
            return socket.emit('error_msg', `Insufficient balance. Need KES ${ENTRY_FEE}.`);
        }
        
        const newBal = await getBalance(socket.phone);
        socket.emit('balance_update', { balance: newBal.toFixed(2) });
        
        const roomCode = generateRoomCode();
        const room = {
            code: roomCode,
            creator: socket.phone,
            creatorSocket: socket.id,
            playerSocket: null,
            playerPhone: null,
            createdAt: Date.now(),
            gameStarted: false
        };
        
        privateRooms.set(roomCode, room);
        socket.currentRoom = roomCode;
        socket.join(`room:${roomCode}`);
        
        console.log(`🏠 Private room created: ${roomCode} by ${socket.phone}`);
        socket.emit('room_created', { roomCode, balance: newBal.toFixed(2) });
        socket.emit('waiting_for_opponent', { roomCode });
    });

    // ─── JOIN PRIVATE ROOM ─────────────────────────────────────────────────
    socket.on('join_private_room', async ({ roomCode }) => {
        if (!socket.authenticated || !socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (socket.searching) return socket.emit('error_msg', 'Already searching.');
        if (socket.currentRoom) return socket.emit('error_msg', 'Already in a room.');
        
        const code = roomCode.toUpperCase();
        const room = privateRooms.get(code);
        
        if (!room) {
            return socket.emit('room_error', { error: 'Room not found or expired.' });
        }
        
        if (room.gameStarted) {
            return socket.emit('room_error', { error: 'Game already in progress.' });
        }
        
        if (room.playerSocket) {
            return socket.emit('room_error', { error: 'Room is full.' });
        }
        
        if (room.creator === socket.phone) {
            return socket.emit('room_error', { error: 'Cannot join your own room.' });
        }
        
        const deducted = await deductBalance(socket.phone, ENTRY_FEE);
        if (!deducted) {
            return socket.emit('error_msg', `Insufficient balance. Need KES ${ENTRY_FEE}.`);
        }
        
        const newBal = await getBalance(socket.phone);
        socket.emit('balance_update', { balance: newBal.toFixed(2) });
        
        room.playerSocket = socket.id;
        room.playerPhone = socket.phone;
        room.gameStarted = true;
        socket.currentRoom = code;
        socket.join(`room:${code}`);
        
        const creatorSocket = io.sockets.sockets.get(room.creatorSocket);
        
        const gameId = `private_${code}_${Date.now()}`;
        const game = {
            board: Array(9).fill(null),
            players: { X: room.creator, O: socket.phone },
            sockets: { X: room.creatorSocket, O: socket.id },
            currentTurn: 'X',
            isPrivate: true,
            roomCode: code
        };
        games.set(gameId, game);
        
        console.log(`✅ Player ${socket.phone} joined private room ${code}`);
        
        socket.emit('private_match_found', {
            gameId,
            mySymbol: 'O',
            opponent: room.creator
        });
        
        if (creatorSocket) {
            creatorSocket.emit('private_match_found', {
                gameId,
                mySymbol: 'X',
                opponent: socket.phone
            });
        }
        
        audit('private_game_started', { roomCode: code, playerX: room.creator, playerO: socket.phone });
    });

    // ─── CANCEL PRIVATE ROOM ───────────────────────────────────────────────
    socket.on('cancel_private_room', async () => {
        if (!socket.authenticated) return;
        const roomCode = socket.currentRoom;
        if (!roomCode) return;
        
        const room = privateRooms.get(roomCode);
        if (room && room.creatorSocket === socket.id && !room.gameStarted) {
            privateRooms.delete(roomCode);
            socket.currentRoom = null;
            socket.leave(`room:${roomCode}`);
            
            await creditBalance(socket.phone, ENTRY_FEE);
            const bal = await getBalance(socket.phone);
            socket.emit('balance_update', { balance: bal.toFixed(2) });
            socket.emit('room_cancelled', {});
            
            console.log(`❌ Private room ${roomCode} cancelled`);
        }
    });

    socket.on('find_match', async () => {
        if (!socket.authenticated || !socket.phone) {
            return socket.emit('error_msg', 'Not authenticated.');
        }
        if (socket.searching) {
            return socket.emit('error_msg', 'Already searching.');
        }
        if (socket.currentRoom) {
            return socket.emit('error_msg', 'Leave current room first.');
        }
        
        socket.searching = true;
        audit('find_match', { phone: socket.phone });
        
        console.log(`🔍 Player ${socket.phone} searching. Current waiting: ${waitingSocket?.phone || 'none'}`);

        const deducted = await deductBalance(socket.phone, ENTRY_FEE);
        if (!deducted) {
            socket.searching = false;
            return socket.emit('error_msg', `Insufficient balance. Need KES ${ENTRY_FEE}.`);
        }

        const newBal = await getBalance(socket.phone);
        socket.emit('balance_update', { balance: newBal.toFixed(2) });

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
                isPrivate: false
            };
            games.set(gameId, game);
            
            console.log(`✅ MATCHED! ${socket.phone} with ${opponent.phone} - Game: ${gameId}`);
            audit('game_started', { gameId, playerX: socket.phone, playerO: opponent.phone });

            io.to(gameId).emit('match_found', {
                gameId,
                playerX: socket.id,
                playerO: opponent.id,
            });
            broadcastOnlineCount();
        } else {
            waitingSocket = socket;
            console.log(`⏳ ${socket.phone} is now waiting for opponent`);
            socket.emit('waiting', {});
            broadcastOnlineCount();
        }
    });

    socket.on('cancel_search', async () => {
        if (!socket.authenticated) return;
        if (!socket.searching) return;
        
        if (waitingSocket && waitingSocket.id === socket.id) {
            waitingSocket = null;
        }
        
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

    socket.on('disconnect', async () => {
        console.log(`🔌 Disconnect: ${socket.id} (${socket.phone || 'no phone'})`);
        
        if (socket.currentRoom) {
            const room = privateRooms.get(socket.currentRoom);
            if (room && !room.gameStarted) {
                privateRooms.delete(socket.currentRoom);
                console.log(`🧹 Cleaned up private room: ${socket.currentRoom}`);
            }
        }
        
        if (waitingSocket && waitingSocket.id === socket.id) {
            waitingSocket = null;
            if (socket.phone && socket.searching) {
                await creditBalance(socket.phone, ENTRY_FEE);
            }
        }
        
        socket.searching = false;
        socket.authenticated = false;

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
                    oppSocket.currentRoom = null;
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
        if (!socket.authenticated || !socket.phone) return;
        const bal = await getBalance(socket.phone);
        socket.emit('balance_update', { balance: bal.toFixed(2) });
    });
});

async function finishGame(gameId, game, result) {
    games.delete(gameId);
    
    if (game.isPrivate && game.roomCode) {
        privateRooms.delete(game.roomCode);
        const sockets = io.sockets.sockets;
        for (const [id, sock] of sockets) {
            if (sock.currentRoom === game.roomCode) {
                sock.currentRoom = null;
                sock.leave(`room:${game.roomCode}`);
            }
        }
    }
    
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

async function start() {
    try {
        await redis.connect();
        console.log('✅ Redis connected');
    } catch(e) {
        console.warn('⚠️ Redis unavailable — using in-memory storage only:', e.message);
    }
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => console.log(`🚀 TicTac Cash running on port ${PORT}`));
}

start();