const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// ============ DATA STORAGE ============
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TOKENS_FILE = path.join(DATA_DIR, 'tokens.json');
const TRANSACTIONS_FILE = path.join(DATA_DIR, 'transactions.json');
const ROUNDS_FILE = path.join(DATA_DIR, 'rounds.json');

function loadJSON(file, defaultVal = {}) {
    try { if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch(e) { console.error(`Error loading ${file}:`, e.message); }
    return defaultVal;
}

function saveJSON(file, data) {
    try { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }
    catch(e) { console.error(`Error saving ${file}:`, e.message); }
}

let users = loadJSON(USERS_FILE);
let authTokens = loadJSON(TOKENS_FILE);
let transactions = loadJSON(TRANSACTIONS_FILE, []);
let savedRounds = loadJSON(ROUNDS_FILE, []);

// ============ CONFIGURATION ============
const CONFIG = {
    appName: 'Aviator',
    version: '3.0.0',
    houseEdge: 0.01,
    minMultiplier: 1.00,
    maxMultiplier: 1000,
    upi: {
        id: process.env.UPI_ID || 'yourname@upi',
        qrImage: '/upi-qr.png',
        merchantName: 'Aviator Gaming',
        minDeposit: 100,
        maxDeposit: 50000,
        minWithdraw: 200,
        maxWithdraw: 25000,
        depositBonus: 10,
        maxAutoPayout: 1000
    },
    modes: {
        classic: { name: 'Classic', minBet: 10, maxBet: 10000, betTime: 8000, curve: 'exponential', icon: '🎯', color: '#00d2ff' },
        turbo: { name: 'Turbo', minBet: 50, maxBet: 5000, betTime: 5000, curve: 'aggressive', icon: '⚡', color: '#ff6b6b' },
        safe: { name: 'Safe Flight', minBet: 100, maxBet: 20000, betTime: 10000, curve: 'linear', icon: '🛡️', color: '#00ff88' },
        jackpot: { name: 'Jackpot', minBet: 10, maxBet: 2000, betTime: 12000, curve: 'power', icon: '💎', color: '#ffd700' }
    }
};

// ============ AUTH HELPERS ============
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    try {
        const [salt, hash] = stored.split(':');
        return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex') === hash;
    } catch(e) { return false; }
}

function generateToken(userId) {
    const token = crypto.randomBytes(32).toString('hex');
    authTokens[token] = { userId, createdAt: Date.now(), ip: '' };
    saveJSON(TOKENS_FILE, authTokens);
    return token;
}

function verifyToken(token) {
    const data = authTokens[token];
    if (!data) return null;
    if (Date.now() - data.createdAt > 30 * 24 * 60 * 60 * 1000) {
        delete authTokens[token];
        saveJSON(TOKENS_FILE, authTokens);
        return null;
    }
    return data.userId;
}

// ============ AUTH API ROUTES ============
app.post('/api/auth/signup', (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });
    
    if (Object.values(users).find(u => u.email === email)) {
        return res.status(400).json({ error: 'Email already registered' });
    }
    if (Object.values(users).find(u => u.username.toLowerCase() === username.toLowerCase())) {
        return res.status(400).json({ error: 'Username already taken' });
    }
    
    const userId = 'U' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(4).toString('hex').toUpperCase();
    
    users[userId] = {
        id: userId,
        username,
        email,
        password: hashPassword(password),
        balance: 0,
        totalWinnings: 0,
        totalLosses: 0,
        totalBets: 0,
        totalDeposits: 0,
        totalWithdrawals: 0,
        level: 1,
        xp: 0,
        vipTier: 'bronze',
        freeBets: 1,
        achievements: [],
        createdAt: Date.now(),
        lastLogin: Date.now(),
        isOnline: false
    };
    
    saveJSON(USERS_FILE, users);
    const token = generateToken(userId);
    
    res.json({
        success: true,
        token,
        user: sanitizeUser(users[userId])
    });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }
    
    const user = Object.values(users).find(u => u.email === email);
    if (!user || !verifyPassword(password, user.password)) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    user.lastLogin = Date.now();
    saveJSON(USERS_FILE, users);
    
    const token = generateToken(user.id);
    res.json({ success: true, token, user: sanitizeUser(user) });
});

app.get('/api/auth/profile', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token provided' });
    
    const userId = verifyToken(token);
    if (!userId || !users[userId]) return res.status(401).json({ error: 'Invalid token' });
    
    res.json(sanitizeUser(users[userId]));
});

app.post('/api/auth/logout', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (token && authTokens[token]) {
        const userId = authTokens[token].userId;
        if (users[userId]) users[userId].isOnline = false;
        delete authTokens[token];
        saveJSON(TOKENS_FILE, authTokens);
        saveJSON(USERS_FILE, users);
    }
    res.json({ success: true });
});

function sanitizeUser(user) {
    if (!user) return null;
    return {
        id: user.id,
        username: user.username,
        email: user.email,
        balance: user.balance,
        level: user.level,
        xp: user.xp,
        vipTier: user.vipTier,
        freeBets: user.freeBets,
        totalWinnings: user.totalWinnings,
        totalLosses: user.totalLosses,
        totalBets: user.totalBets,
        totalDeposits: user.totalDeposits,
        totalWithdrawals: user.totalWithdrawals,
        achievements: user.achievements,
        createdAt: user.createdAt
    };
}

// ============ GAME ENGINE ============
class AviatorEngine {
    constructor() {
        this.currentRound = null;
        this.roundHistory = savedRounds.slice(-500);
        this.totalRounds = this.roundHistory.length;
        this.leaderboard = [];
        this.chatMessages = [];
        this.playerWS = new Map();
        this.currentMode = 'classic';
        this.totalWagered = 0;
        this.totalPaidOut = 0;
        this.buildLeaderboard();
    }

    buildLeaderboard() {
        this.leaderboard = Object.values(users)
            .map(u => ({ id: u.id, username: u.username, winnings: u.totalWinnings, level: u.level, vipTier: u.vipTier }))
            .sort((a, b) => b.winnings - a.winnings)
            .slice(0, 100);
    }

    generateSeeds() {
        const serverSeed = crypto.randomBytes(32).toString('hex');
        const serverSeedHash = crypto.createHash('sha256').update(serverSeed).digest('hex');
        const clientSeed = this.roundHistory.length > 0 
            ? this.roundHistory[this.roundHistory.length - 1].nextClientSeed 
            : crypto.randomBytes(16).toString('hex');
        const nextClientSeed = crypto.randomBytes(16).toString('hex');
        return { serverSeed, serverSeedHash, clientSeed, nextClientSeed };
    }

    generateCrashPoint(serverSeed, clientSeed, roundId) {
        const mode = CONFIG.modes[this.currentMode];
        const hmac = crypto.createHmac('sha512', serverSeed)
            .update(`${clientSeed}-${roundId}-${mode.name}`)
            .digest('hex');
        
        const randomValue = parseInt(hmac.substring(0, 13), 16) / Math.pow(2, 52);
        let crashPoint;

        switch(mode.curve) {
            case 'aggressive': crashPoint = (0.99 / Math.pow(1 - randomValue, 0.83)) * (1 - CONFIG.houseEdge); break;
            case 'linear': crashPoint = (1 + randomValue * 100) * (1 - CONFIG.houseEdge); break;
            case 'power': crashPoint = Math.pow(1 / (1 - randomValue), 2) * (1 - CONFIG.houseEdge); break;
            default: crashPoint = (0.99 / (1 - randomValue)) * (1 - CONFIG.houseEdge);
        }

        return Math.max(CONFIG.minMultiplier, Math.min(CONFIG.maxMultiplier, Math.floor(crashPoint * 100) / 100));
    }

    startNewRound() {
        const seeds = this.generateSeeds();
        const roundId = Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
        const crashPoint = this.generateCrashPoint(seeds.serverSeed, seeds.clientSeed, roundId);
        
        this.totalRounds++;
        this.currentRound = {
            roundId, ...seeds, crashPoint,
            status: 'waiting', startTime: null,
            bets: new Map(), mode: this.currentMode
        };

        return {
            roundId,
            serverSeedHash: seeds.serverSeedHash,
            clientSeed: seeds.clientSeed,
            crashPoint,
            bettingTime: CONFIG.modes[this.currentMode].betTime,
            mode: this.currentMode
        };
    }

    placeBet(playerId, amount, autoCashout = null) {
        if (!this.currentRound || this.currentRound.status !== 'waiting') throw new Error('Bets are closed');
        
        const mode = CONFIG.modes[this.currentMode];
        if (amount < mode.minBet || amount > mode.maxBet) throw new Error(`Bet ₹${mode.minBet}-₹${mode.maxBet}`);
        
        const user = users[playerId];
        if (!user) throw new Error('Player not found');
        if (user.balance < amount) throw new Error('Insufficient balance. Please deposit.');
        
        user.balance -= amount;
        user.totalBets++;
        this.totalWagered += amount;
        
        this.currentRound.bets.set(playerId, { playerId, amount, autoCashout, cashoutMultiplier: null, profit: null, timestamp: Date.now() });
        saveJSON(USERS_FILE, users);
        
        return { amount, newBalance: user.balance, autoCashout };
    }

    cashout(playerId) {
        if (!this.currentRound || this.currentRound.status !== 'running') throw new Error('Round not active');
        
        const bet = this.currentRound.bets.get(playerId);
        if (!bet) throw new Error('No active bet');
        if (bet.cashoutMultiplier !== null) throw new Error('Already cashed out');
        
        const multiplier = this.getCurrentMultiplier();
        bet.cashoutMultiplier = multiplier;
        bet.profit = bet.amount * multiplier;
        
        const user = users[playerId];
        user.balance += bet.profit;
        user.totalWinnings += bet.profit - bet.amount;
        this.totalPaidOut += bet.profit;
        user.xp += Math.floor(bet.profit / 10);
        
        const newLevel = Math.floor(user.xp / 1000) + 1;
        const leveledUp = newLevel > user.level;
        if (leveledUp) { user.level = newLevel; user.freeBets += 1; }
        
        if (user.totalDeposits >= 50000) user.vipTier = 'diamond';
        else if (user.totalDeposits >= 25000) user.vipTier = 'platinum';
        else if (user.totalDeposits >= 10000) user.vipTier = 'gold';
        else if (user.totalDeposits >= 5000) user.vipTier = 'silver';
        
        saveJSON(USERS_FILE, users);
        this.buildLeaderboard();
        
        return { multiplier, profit: bet.profit, newBalance: user.balance, levelUp: leveledUp, newLevel: user.level, vipTier: user.vipTier };
    }

    getCurrentMultiplier() {
        if (!this.currentRound?.startTime) return 1.00;
        const elapsed = (Date.now() - this.currentRound.startTime) / 1000;
        const curve = CONFIG.modes[this.currentMode].curve;
        const t = elapsed * 0.1;
        
        let m;
        switch(curve) {
            case 'aggressive': m = Math.pow(Math.E, t * 0.8) / 100 + 1; break;
            case 'linear': m = 1 + t * 0.5; break;
            case 'power': m = Math.pow(t + 1, 1.5) / 10 + 1; break;
            default: m = Math.pow(Math.E, t * 0.6) / 100 + 1;
        }
        return Math.floor(m * 100) / 100;
    }

    endRound() {
        if (!this.currentRound) return null;
        this.currentRound.status = 'crashed';
        this.currentRound.endTime = Date.now();
        
        const results = [];
        this.currentRound.bets.forEach((bet, pid) => {
            const user = users[pid];
            const result = {
                playerId: pid,
                cashedOut: bet.cashoutMultiplier !== null,
                multiplier: bet.cashoutMultiplier || 0,
                profit: bet.cashoutMultiplier ? bet.profit - bet.amount : -bet.amount,
                balance: user?.balance || 0
            };
            if (!bet.cashoutMultiplier && user) user.totalLosses += bet.amount;
            results.push(result);
        });
        
        const roundRecord = {
            roundId: this.currentRound.roundId,
            crashPoint: this.currentRound.crashPoint,
            serverSeed: this.currentRound.serverSeed,
            serverSeedHash: this.currentRound.serverSeedHash,
            clientSeed: this.currentRound.clientSeed,
            nextClientSeed: this.currentRound.nextClientSeed,
            mode: this.currentMode,
            timestamp: Date.now(),
            totalBets: this.currentRound.bets.size
        };
        
        this.roundHistory.push(roundRecord);
        if (this.roundHistory.length > 500) this.roundHistory.shift();
        savedRounds.push(roundRecord);
        if (savedRounds.length > 500) savedRounds.splice(0, savedRounds.length - 500);
        
        saveJSON(ROUNDS_FILE, savedRounds);
        saveJSON(USERS_FILE, users);
        
        return results;
    }

    verifyRound(roundId, serverSeed, clientSeed, expectedCrash) {
        const round = this.roundHistory.find(r => r.roundId === roundId);
        if (!round) throw new Error('Round not found');
        
        const mode = CONFIG.modes[round.mode] || CONFIG.modes.classic;
        const hmac = crypto.createHmac('sha512', serverSeed)
            .update(`${clientSeed}-${roundId}-${mode.name}`)
            .digest('hex');
        
        const randomValue = parseInt(hmac.substring(0, 13), 16) / Math.pow(2, 52);
        let calculated;
        
        switch(mode.curve) {
            case 'aggressive': calculated = (0.99 / Math.pow(1 - randomValue, 0.83)) * (1 - CONFIG.houseEdge); break;
            case 'linear': calculated = (1 + randomValue * 100) * (1 - CONFIG.houseEdge); break;
            case 'power': calculated = Math.pow(1 / (1 - randomValue), 2) * (1 - CONFIG.houseEdge); break;
            default: calculated = (0.99 / (1 - randomValue)) * (1 - CONFIG.houseEdge);
        }
        
        calculated = Math.max(CONFIG.minMultiplier, Math.min(CONFIG.maxMultiplier, Math.floor(calculated * 100) / 100));
        
        return {
            isValid: Math.abs(calculated - expectedCrash) < 0.01,
            calculatedCrash: calculated,
            expectedCrash,
            serverSeedVerified: serverSeed === round.serverSeed,
            clientSeedVerified: clientSeed === round.clientSeed,
            roundMode: round.mode,
            houseEdge: CONFIG.houseEdge
        };
    }

    // Payment Methods
    genTxnId() { return 'AVI' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(3).toString('hex').toUpperCase(); }

    generateUPI(amount, txnId) {
        const params = new URLSearchParams({
            pa: CONFIG.upi.id, pn: CONFIG.upi.merchantName, tr: txnId,
            tn: 'Add Cash', am: amount.toFixed(2), cu: 'INR', mode: '02'
        });
        return {
            upiIntent: `upi://pay?${params.toString()}`,
            upiId: CONFIG.upi.id,
            amount,
            transactionId: txnId,
            qrImage: CONFIG.upi.qrImage,
            qrFallback: `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(`upi://pay?${params.toString()}`)}`
        };
    }

    processDeposit(playerId, amount) {
        if (amount < CONFIG.upi.minDeposit) throw new Error(`Min deposit: ₹${CONFIG.upi.minDeposit}`);
        if (amount > CONFIG.upi.maxDeposit) throw new Error(`Max deposit: ₹${CONFIG.upi.maxDeposit}`);
        
        const txnId = this.genTxnId();
        const bonus = Math.floor(amount * CONFIG.upi.depositBonus / 100);
        
        transactions.push({
            transactionId: txnId, playerId, type: 'deposit',
            amount, bonus, totalCredit: amount + bonus,
            status: 'pending', timestamp: Date.now(),
            expiresAt: Date.now() + 30 * 60 * 1000
        });
        saveJSON(TRANSACTIONS_FILE, transactions);
        
        return {
            transactionId: txnId, amount, bonus, totalCredit: amount + bonus,
            upiDetails: this.generateUPI(amount, txnId), status: 'pending'
        };
    }

    confirmDeposit(txnId, upiRef) {
        const txn = transactions.find(t => t.transactionId === txnId);
        if (!txn) throw new Error('Transaction not found');
        if (txn.status === 'completed') throw new Error('Already processed');
        if (Date.now() > txn.expiresAt) throw new Error('Transaction expired');
        
        txn.status = 'completed';
        txn.completedAt = Date.now();
        txn.upiReference = upiRef;
        
        const user = users[txn.playerId];
        user.balance += txn.totalCredit;
        user.totalDeposits += txn.amount;
        user.xp += Math.floor(txn.amount / 10);
        
        const newLevel = Math.floor(user.xp / 1000) + 1;
        if (newLevel > user.level) { user.level = newLevel; user.freeBets += 1; }
        
        if (user.totalDeposits >= 50000) user.vipTier = 'diamond';
        else if (user.totalDeposits >= 25000) user.vipTier = 'platinum';
        else if (user.totalDeposits >= 10000) user.vipTier = 'gold';
        else if (user.totalDeposits >= 5000) user.vipTier = 'silver';
        
        saveJSON(TRANSACTIONS_FILE, transactions);
        saveJSON(USERS_FILE, users);
        
        return {
            transactionId: txnId, status: 'completed',
            credited: txn.totalCredit, bonus: txn.bonus,
            newBalance: user.balance, newLevel: user.level,
            vipTier: user.vipTier, freeBets: user.freeBets
        };
    }

    requestWithdrawal(playerId, amount, upiId) {
        if (amount < CONFIG.upi.minWithdraw) throw new Error(`Min withdrawal: ₹${CONFIG.upi.minWithdraw}`);
        if (amount > CONFIG.upi.maxWithdraw) throw new Error(`Max withdrawal: ₹${CONFIG.upi.maxWithdraw}`);
        
        const user = users[playerId];
        if (!user || user.balance < amount) throw new Error('Insufficient balance');
        
        const txnId = this.genTxnId();
        user.balance -= amount;
        user.totalWithdrawals += amount;
        
        const autoApproved = amount <= CONFIG.upi.maxAutoPayout;
        
        transactions.push({
            transactionId: txnId, playerId, type: 'withdrawal',
            amount, status: autoApproved ? 'approved' : 'processing',
            upiId, timestamp: Date.now(), autoApproved
        });
        
        saveJSON(TRANSACTIONS_FILE, transactions);
        saveJSON(USERS_FILE, users);
        
        return {
            transactionId: txnId, amount,
            status: autoApproved ? 'approved' : 'processing',
            newBalance: user.balance, autoApproved,
            message: autoApproved ? 'Withdrawal approved! Credited to your UPI.' : 'Processing. Credited within 24 hours.'
        };
    }

    getTransactions(playerId, limit = 30) {
        return transactions.filter(t => t.playerId === playerId).slice(-limit).reverse();
    }

    getLeaderboard(limit = 20) {
        this.buildLeaderboard();
        return this.leaderboard.slice(0, limit).map((p, i) => ({ ...p, rank: i + 1 }));
    }

    getStats() {
        return {
            totalRounds: this.totalRounds,
            onlinePlayers: this.playerWS.size,
            totalWagered: this.totalWagered,
            totalPaidOut: this.totalPaidOut,
            currentMode: this.currentMode,
            houseEdge: CONFIG.houseEdge,
            modes: CONFIG.modes,
            upi: { id: CONFIG.upi.id, minDeposit: CONFIG.upi.minDeposit, maxDeposit: CONFIG.upi.maxDeposit, depositBonus: CONFIG.upi.depositBonus }
        };
    }
}

// ============ INITIALIZE ============
const engine = new AviatorEngine();

// ============ GAME LOOP ============
let gameInterval, bettingTimeout, roundTimeout;
let currentMultiplier = 1.00;

function broadcast(data, excludeId = null) {
    const msg = JSON.stringify(data);
    wss.clients.forEach(c => {
        if (c.readyState === WebSocket.OPEN && c.playerId !== excludeId) c.send(msg);
    });
}

function sendTo(pid, data) {
    const ws = engine.playerWS.get(pid);
    if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
}

function startLoop() {
    const rd = engine.startNewRound();
    currentMultiplier = 1.00;
    
    broadcast({
        type: 'ROUND_STARTING',
        roundId: rd.roundId,
        serverSeedHash: rd.serverSeedHash,
        bettingTime: rd.bettingTime,
        crashPoint: rd.crashPoint,
        mode: rd.mode
    });
    
    bettingTimeout = setTimeout(() => {
        if (!engine.currentRound) return;
        engine.currentRound.status = 'running';
        engine.currentRound.startTime = Date.now();
        broadcast({ type: 'ROUND_STARTED', roundId: engine.currentRound.roundId });
        
        gameInterval = setInterval(() => {
            currentMultiplier = engine.getCurrentMultiplier();
            broadcast({ type: 'MULTIPLIER', value: currentMultiplier });
            if (currentMultiplier >= engine.currentRound.crashPoint) crash();
        }, 100);
    }, rd.bettingTime);
}

function crash() {
    clearInterval(gameInterval);
    const cp = engine.currentRound.crashPoint;
    const results = engine.endRound();
    const rd = engine.currentRound;
    
    broadcast({
        type: 'CRASHED',
        crashPoint: cp, results,
        serverSeed: rd.serverSeed,
        clientSeed: rd.clientSeed,
        roundId: rd.roundId
    });
    
    broadcast({
        type: 'HISTORY',
        history: engine.roundHistory.slice(-30).map(r => ({
            roundId: r.roundId, crashPoint: r.crashPoint,
            mode: r.mode, serverSeedHash: r.serverSeedHash,
            clientSeed: r.clientSeed, timestamp: r.timestamp
        }))
    });
    
    broadcast({ type: 'LEADERBOARD', leaderboard: engine.getLeaderboard() });
    roundTimeout = setTimeout(startLoop, 3000);
}

// ============ WEBSOCKET ============
wss.on('connection', (ws) => {
    let playerId = null, authed = false;
    
    ws.on('message', (msg) => {
        try {
            const data = JSON.parse(msg);
            
            if (data.type === 'AUTH') {
                const uid = verifyToken(data.token);
                if (!uid || !users[uid]) {
                    return ws.send(JSON.stringify({ type: 'AUTH_ERROR', message: 'Invalid session. Please login again.' }));
                }
                playerId = uid;
                authed = true;
                ws.playerId = playerId;
                engine.playerWS.set(playerId, ws);
                users[playerId].isOnline = true;
                saveJSON(USERS_FILE, users);
                
                const u = users[playerId];
                ws.send(JSON.stringify({
                    type: 'AUTH_SUCCESS',
                    user: sanitizeUser(u),
                    history: engine.roundHistory.slice(-30).map(r => ({
                        roundId: r.roundId, crashPoint: r.crashPoint, mode: r.mode,
                        serverSeedHash: r.serverSeedHash, clientSeed: r.clientSeed, timestamp: r.timestamp
                    })),
                    leaderboard: engine.getLeaderboard(),
                    currentRound: engine.currentRound ? {
                        roundId: engine.currentRound.roundId, status: engine.currentRound.status,
                        multiplier: currentMultiplier, mode: engine.currentMode
                    } : null,
                    upiConfig: {
                        upiId: CONFIG.upi.id, qrImage: CONFIG.upi.qrImage,
                        minDeposit: CONFIG.upi.minDeposit, maxDeposit: CONFIG.upi.maxDeposit,
                        depositBonus: CONFIG.upi.depositBonus
                    },
                    modes: CONFIG.modes
                }));
                
                broadcast({
                    type: 'CHAT',
                    message: { type: 'system', playerName: 'System', text: `${u.username} joined! 👋`, timestamp: Date.now() }
                });
                return;
            }
            
            if (!authed) return ws.send(JSON.stringify({ type: 'ERROR', message: 'Please login first' }));
            
            switch(data.type) {
                case 'BET':
                    try {
                        const r = engine.placeBet(playerId, data.amount, data.autoCashout);
                        sendTo(playerId, { type: 'BET_CONFIRMED', ...r });
                        broadcast({ type: 'PLAYER_BET', playerName: users[playerId].username, amount: data.amount, vipTier: users[playerId].vipTier }, playerId);
                    } catch(e) { sendTo(playerId, { type: 'ERROR', message: e.message }); }
                    break;
                    
                case 'CASHOUT':
                    try {
                        const r = engine.cashout(playerId);
                        sendTo(playerId, { type: 'CASHOUT_SUCCESS', ...r });
                        broadcast({ type: 'PLAYER_CASHOUT', playerName: users[playerId].username, multiplier: r.multiplier, profit: r.profit, vipTier: users[playerId].vipTier }, playerId);
                    } catch(e) { sendTo(playerId, { type: 'ERROR', message: e.message }); }
                    break;
                    
                case 'CHAT':
                    const cm = { type: 'player', playerName: users[playerId].username, text: data.text?.substring(0, 200) || '', timestamp: Date.now(), level: users[playerId].level, vipTier: users[playerId].vipTier };
                    engine.chatMessages.push(cm);
                    if (engine.chatMessages.length > 200) engine.chatMessages.shift();
                    broadcast({ type: 'CHAT', message: cm });
                    break;
                    
                case 'VERIFY':
                    try {
                        const vr = engine.verifyRound(data.roundId, data.serverSeed, data.clientSeed, data.crashPoint);
                        sendTo(playerId, { type: 'VERIFICATION_RESULT', ...vr });
                    } catch(e) { sendTo(playerId, { type: 'ERROR', message: e.message }); }
                    break;
                    
                case 'SET_MODE':
                    if (CONFIG.modes[data.mode]) { engine.currentMode = data.mode; broadcast({ type: 'MODE_CHANGED', mode: data.mode }); }
                    break;
                    
                case 'GET_LEADERBOARD':
                    sendTo(playerId, { type: 'LEADERBOARD', leaderboard: engine.getLeaderboard() });
                    break;
                    
                case 'DEPOSIT_REQUEST':
                    try {
                        const d = engine.processDeposit(playerId, data.amount);
                        sendTo(playerId, { type: 'DEPOSIT_INITIATED', ...d });
                    } catch(e) { sendTo(playerId, { type: 'ERROR', message: e.message }); }
                    break;
                    
                case 'CONFIRM_DEPOSIT':
                    try {
                        const cd = engine.confirmDeposit(data.transactionId, data.upiReference);
                        sendTo(playerId, { type: 'DEPOSIT_CONFIRMED', ...cd });
                        broadcast({ type: 'CHAT', message: { type: 'system', playerName: '💰', text: `${users[playerId].username} deposited ₹${data.amount}!`, timestamp: Date.now() } });
                    } catch(e) { sendTo(playerId, { type: 'ERROR', message: e.message }); }
                    break;
                    
                case 'WITHDRAW_REQUEST':
                    try {
                        const w = engine.requestWithdrawal(playerId, data.amount, data.upiId);
                        sendTo(playerId, { type: 'WITHDRAWAL_INITIATED', ...w });
                    } catch(e) { sendTo(playerId, { type: 'ERROR', message: e.message }); }
                    break;
                    
                case 'GET_TRANSACTIONS':
                    sendTo(playerId, { type: 'TRANSACTION_HISTORY', transactions: engine.getTransactions(playerId) });
                    break;
                    
                case 'USE_FREE_BET':
                    if (users[playerId].freeBets > 0) {
                        users[playerId].freeBets--;
                        saveJSON(USERS_FILE, users);
                        sendTo(playerId, { type: 'FREE_BET_ACTIVATED', freeBets: users[playerId].freeBets });
                    } else {
                        sendTo(playerId, { type: 'ERROR', message: 'No free bets available' });
                    }
                    break;
                    
                case 'GET_STATS':
                    sendTo(playerId, { type: 'STATS', stats: engine.getStats() });
                    break;
            }
        } catch(e) {
            ws.send(JSON.stringify({ type: 'ERROR', message: 'Invalid message' }));
        }
    });
    
    ws.on('close', () => {
        if (playerId) {
            engine.playerWS.delete(playerId);
            if (users[playerId]) { users[playerId].isOnline = false; saveJSON(USERS_FILE, users); }
        }
    });
});

// ============ API ROUTES ============
app.get('/api/history', (req, res) => res.json(engine.roundHistory.slice(-50)));
app.get('/api/leaderboard', (req, res) => res.json(engine.getLeaderboard(50)));
app.get('/api/stats', (req, res) => res.json(engine.getStats()));
app.get('/api/modes', (req, res) => res.json(CONFIG.modes));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// ============ START ============
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log('═══════════════════════════════════════════');
    console.log(`  ✈️  ${CONFIG.appName} v${CONFIG.version}`);
    console.log(`  🌐 http://localhost:${PORT}`);
    console.log(`  🔐 Auth: JWT + File DB`);
    console.log(`  💳 UPI: ${CONFIG.upi.id}`);
    console.log(`  🎁 Bonus: ${CONFIG.upi.depositBonus}%`);
    console.log(`  🔒 CSPRNG: HMAC-SHA512`);
    console.log('═══════════════════════════════════════════');
    startLoop();
});