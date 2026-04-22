require('dotenv').config();
const express  = require('express');
const http     = require('http');
const { Server } = require('socket.io');
const { createClient } = require('redis');
const { createAdapter } = require('@socket.io/redis-adapter'); // Added
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
const subClient = redis.duplicate(); // Required for the adapter

redis.on('error',   e => console.error('Redis error:', e.message));
subClient.on('error', e => console.error('Redis Sub error:', e.message));

// ─── STATE MANAGEMENT ─────────────────────────────────────────────────────
// REMOVED: let waitingSocket = null; (Now managed via Redis)
const games = new Map(); 
const balances = new Map(); 

// ... [Keep your existing security/helper functions here] ...

// ─── SOCKET EVENTS ────────────────────────────────────────────────────────
io.on('connection', (socket) => {
    broadcastOnlineCount();

    socket.on('auth', async ({ phone }) => {
        const normalizedPhone = normalizePhone(phone);
        if (!normalizedPhone) return socket.emit('error_msg', 'Invalid phone.');
        
        socket.phone = normalizedPhone;
        // Join a room named after the phone number to allow cross-instance messaging
        socket.join(`phone:${normalizedPhone}`);

        // ... [Keep your existing demo bonus logic here] ...

        const bal = await getBalance(normalizedPhone);
        socket.emit('auth_success', { balance: bal.toFixed(2) });
    });

    socket.on('find_match', async () => {
        if (!socket.phone) return socket.emit('error_msg', 'Not authenticated.');
        if (socket.searching) return;

        const deducted = await deductBalance(socket.phone, ENTRY_FEE);
        if (!deducted) return socket.emit('error_msg', `Insufficient balance.`);

        socket.searching = true;
        
        // 1. Check Redis for a waiting player
        const opponentPhone = await redis.get('matchmaking:waiting');

        if (opponentPhone && opponentPhone !== socket.phone) {
            // 2. Try to claim the match (Atomic delete to prevent double-matching)
            const claimed = await redis.del('matchmaking:waiting');
            
            if (claimed) {
                const gameId = `game_${crypto.randomUUID()}`;
                
                // Emit to both players' specific phone rooms
                io.to(`phone:${socket.phone}`).to(`phone:${opponentPhone}`).emit('match_found', {
                    gameId,
                    playerX: socket.phone,
                    playerO: opponentPhone
                });

                const game = {
                    board: Array(9).fill(null),
                    players: { X: socket.phone, O: opponentPhone },
                    currentTurn: 'X',
                };
                games.set(gameId, game);
                audit('game_started', { gameId, x: socket.phone, o: opponentPhone });
            }
        } else {
            // 3. No one waiting - set this phone as waiting in Redis
            // Set with 60-second expiry so the queue doesn't get stuck if someone crashes
            await redis.set('matchmaking:waiting', socket.phone, { EX: 60 }); 
            socket.emit('waiting', {});
        }
        broadcastOnlineCount();
    });

    socket.on('cancel_search', async () => {
        const waitingPhone = await redis.get('matchmaking:waiting');
        if (waitingPhone === socket.phone) {
            await redis.del('matchmaking:waiting');
        }
        socket.searching = false;
        await creditBalance(socket.phone, ENTRY_FEE);
        socket.emit('search_cancelled', {});
        broadcastOnlineCount();
    });

    // ... [Keep make_move and disconnect logic, but use phone rooms for emits] ...
});

// ─── START FUNCTION ───────────────────────────────────────────────────────
async function start() {
    try {
        // Connect both clients
        await Promise.all([redis.connect(), subClient.connect()]);
        
        // Setup the adapter to sync Socket.IO events across all instances
        io.adapter(createAdapter(redis, subClient));
        
        console.log('Redis and Socket.IO Adapter connected');
    } catch(e) {
        console.warn('Matchmaking may fail - Redis connection issue:', e.message);
    }
    
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

start();