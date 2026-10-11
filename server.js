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
        const hashedPassword = bcrypt.hashSync('admin123', 10);
        const initialData = { 
            accs: [
                { username: 'admin', password: hashedPassword, role: 'admin', balance: 1000000000, is2FAEnabled: false, secret2fa: null }
            ], 
            prods: [
                { id: '1', name: 'Tài khoản Netflix Premium 1 Tháng', price: 69000, stock: 'Có sẵn' },
                { id: '2', name: 'Key Windows 11 Pro Bản Quyền Vĩnh Viễn', price: 150000, stock: 'Có sẵn' }
            ], 
            history: [], 
            blacklist: [], 
            logs: [] 
        };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
    }
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!data.blacklist) data.blacklist = [];
    if (!data.logs) data.logs = [];
    if (!data.prods) data.prods = [];
    if (!data.history) data.history = [];
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
    if (clientIP === '127.0.0.1' || clientIP === '::1' || clientIP.startsWith('::ffff:127.0.0.1')) {
        return next();
    }
    const db = readDB();
    if (db.blacklist && db.blacklist.includes(clientIP)) {
        return res.status(403).json({ success: false, message: 'Truy cập bị từ chối vĩnh viễn do hành vi xâm nhập!' });
    }
    next();
}

app.use(securityShield);

function banAttacker(req, reason) {
    const clientIP = getClientIP(req);
    if (clientIP === '127.0.0.1' || clientIP === '::1' || clientIP.startsWith('::ffff:127.0.0.1')) return;
    const db = readDB();
    if (!db.blacklist.includes(clientIP)) db.blacklist.push(clientIP);
    db.logs.push({ ip: clientIP, time: new Date().toLocaleString(), path: req.originalUrl, reason });
    writeDB(db);
}

function verifyToken(req, res, next) {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Chưa xác thực!' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
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

// ==================== TRANG BẪY HONEYPOT (DỤ KẺ GIAN) ====================
app.all('/api/secret-admin-trap', (req, res) => {
    banAttacker(req, 'Phát hiện truy cập vào điểm bẫy Honeypot mật khẩu gốc!');
    res.status(403).json({
        success: false,
        message: 'CẢNH BÁO: IP và dấu vết thiết bị của bạn đã bị ghi nhận và đưa vào danh sách đen vĩnh viễn vì hành vi quét hệ thống!'
    });
});

// ==================== API CHÍNH ====================
app.get('/api/products', (req, res) => {
    const db = readDB();
    res.json({ success: true, prods: db.prods });
});

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
    
    // Lọc lịch sử mua hàng riêng của user này
    const userHistory = db.history.filter(h => h.username === user.username);

    res.json({ 
        success: true, 
        user: { 
            username: user.username, 
            role: user.role, 
            balance: user.balance, 
            is2FAEnabled: user.is2FAEnabled,
            history: userHistory
        } 
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true, message: 'Đăng xuất thành công' });
});

app.post('/api/2fa/setup', verifyToken, async (req, res) => {
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);
    const secret = speakeasy.generateSecret({ name: `MinhAnhStore (${user.username})` });
    user.tempSecret = secret.base32;
    writeDB(db);

    QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
        if (err) return res.status(500).json({ success: false, message: 'Lỗi tạo QR' });
        res.json({ success: true, qrCodeUrl: data_url });
    });
});

app.post('/api/2fa/verify', verifyToken, (req, res) => {
    const { otpToken } = req.body;
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);
    if (!user || !user.tempSecret) return res.json({ success: false, message: 'Chưa khởi tạo 2FA' });

    const verified = speakeasy.totp.verify({ secret: user.tempSecret, encoding: 'base32', token: otpToken, window: 1 });
    if (verified) {
        user.secret2fa = user.tempSecret;
        user.is2FAEnabled = true;
        delete user.tempSecret;
        writeDB(db);
        return res.json({ success: true, message: 'Bật 2FA thành công!' });
    }
    res.json({ success: false, message: 'Mã OTP không chính xác!' });
});

app.post('/api/change-password', verifyToken, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);

    if (!bcrypt.compareSync(oldPassword, user.password)) {
        return res.json({ success: false, message: 'Mật khẩu cũ không chính xác!' });
    }
    user.password = bcrypt.hashSync(newPassword, 10);
    writeDB(db);
    res.json({ success: true, message: 'Đổi mật khẩu thành công!' });
});

app.post('/api/buy', verifyToken, (req, res) => {
    const { productId } = req.body;
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);
    const product = db.prods.find(p => p.id === productId);

    if (!product) return res.json({ success: false, message: 'Sản phẩm không tồn tại!' });
    if (user.balance < product.price) return res.json({ success: false, message: 'Số dư không đủ!' });

    user.balance -= product.price;
    db.history.push({ username: user.username, productName: product.name, price: product.price, time: new Date().toLocaleString() });
    writeDB(db);
    res.json({ success: true, message: `Mua thành công ${product.name}`, newBalance: user.balance });
});

app.post('/api/admin/add-product', verifyAdmin, (req, res) => {
    const { name, price, stock } = req.body;
    if (!name || !price) return res.json({ success: false, message: 'Thiếu thông tin!' });
    const db = readDB();
    db.prods.push({ id: Date.now().toString(), name, price: Number(price), stock: stock || 'Có sẵn' });
    writeDB(db);
    res.json({ success: true, message: 'Thêm sản phẩm thành công!' });
});

app.listen(PORT, () => {
    console.log(`Server chạy an toàn tại cổng ${PORT}`);
});
