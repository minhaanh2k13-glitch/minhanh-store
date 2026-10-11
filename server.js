const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'minhanh_store_super_secret_key_2026';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const DB_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DB_DIR, 'database.json');

function readDB() {
    if (!fs.existsSync(DB_DIR)) {
        fs.mkdirSync(DB_DIR, { recursive: true });
    }
    if (!fs.existsSync(DB_FILE)) {
        // Chỉ tạo duy nhất 1 tài khoản admin
        const hashedPassword = bcrypt.hashSync('admin123', 10);

        const initialData = { 
            accs: [
                { username: 'admin', password: hashedPassword, role: 'admin', balance: 1000000, is2FAEnabled: false, secret2fa: null }
            ], 
            prods: [], 
            history: [], 
            txs: [], 
            blacklist: [], 
            logs: [] 
        };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
    }
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!data.blacklist) data.blacklist = [];
    if (!data.logs) data.logs = [];
    return data;
}

function writeDB(data) {
    if (!fs.existsSync(DB_DIR)) {
        fs.mkdirSync(DB_DIR, { recursive: true });
    }
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function getClientIP(req) {
    const xForwardedFor = req.headers['x-forwarded-for'];
    if (xForwardedFor) return xForwardedFor.split(',')[0].trim();
    return req.socket.remoteAddress || 'Unknown IP';
}

function securityShield(req, res, next) {
    const clientIP = getClientIP(req);
    const db = readDB();
    if (db.blacklist.includes(clientIP)) {
        return res.status(403).json({ success: false, message: 'IP của bạn đã bị chặn vĩnh viễn!' });
    }
    next();
}

app.use(securityShield);

function banAttacker(req, reason) {
    const clientIP = getClientIP(req);
    const db = readDB();
    if (!db.blacklist.includes(clientIP)) db.blacklist.push(clientIP);
    db.logs.push({ ip: clientIP, time: new Date().toLocaleString(), path: req.originalUrl, reason });
    writeDB(db);
}

function verifyToken(req, res, next) {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) {
        banAttacker(req, 'Truy cập không có Token');
        return res.status(401).json({ success: false, message: 'Chưa xác thực!' });
    }
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        banAttacker(req, 'Token giả mạo hoặc hết hạn');
        return res.status(403).json({ success: false, message: 'Phiên không hợp lệ!' });
    }
}

function verifyAdmin(req, res, next) {
    verifyToken(req, res, () => {
        if (req.user.role !== 'admin') {
            banAttacker(req, 'User thường cố tình gọi API Admin');
            return res.status(403).json({ success: false, message: 'Từ chối quyền truy cập!' });
        }
        next();
    });
}

// API Đăng nhập
app.post('/api/login', async (req, res) => {
    const { username, password, otpToken } = req.body;
    const db = readDB();
    const user = db.accs.find(x => x.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.json({ success: false, message: 'Sai tên đăng nhập hoặc mật khẩu!' });
    }

    if (user.is2FAEnabled) {
        if (!otpToken) return res.json({ require2FA: true, message: 'Yêu cầu mã Google Authenticator!' });
        const verified = speakeasy.totp.verify({ secret: user.secret2fa, encoding: 'base32', token: otpToken, window: 1 });
        if (!verified) return res.json({ success: false, message: 'Mã Google Authenticator không chính xác!' });
    }

    const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
    
    res.json({ success: true, user: { username: user.username, role: user.role, balance: user.balance } });
});

app.get('/api/me', verifyToken, (req, res) => {
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy' });
    res.json({ success: true, user: { username: user.username, role: user.role, balance: user.balance, is2FAEnabled: user.is2FAEnabled } });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true, message: 'Đăng xuất thành công' });
});

app.post('/api/admin/add-product', verifyAdmin, (req, res) => {
    const { name, price, stock } = req.body;
    if (!name || !price) return res.json({ success: false, message: 'Thiếu thông tin!' });

    const db = readDB();
    db.prods.push({ id: Date.now().toString(), name, price: Number(price), stock: stock || '' });
    writeDB(db);
    res.json({ success: true, message: 'Thêm sản phẩm thành công!' });
});

app.listen(PORT, () => {
    console.log(`Server chạy an toàn tuyệt đối tại cổng ${PORT}`);
});
