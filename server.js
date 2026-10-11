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

// Khởi tạo cơ sở dữ liệu an toàn
function readDB() {
    if (!fs.existsSync(DB_DIR)) {
        fs.mkdirSync(DB_DIR, { recursive: true });
    }
    if (!fs.existsSync(DB_FILE)) {
        const hashedPassword = bcrypt.hashSync('admin123', 10);
        const initialData = { 
            accs: [
                { username: 'admin', password: hashedPassword, role: 'admin', balance: 1000000, is2FAEnabled: false, secret2fa: null }
            ], 
            prods: [
                { id: '1', name: 'Tài khoản Netflix Premium 1 Tháng', price: 69000, stock: 'Có sẵn' },
                { id: '2', name: 'Key Windows 11 Pro Bản Quyền Vĩnh Viễn', price: 150000, stock: 'Có sẵn' }
            ], 
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
    if (!data.prods) data.prods = [];
    return data;
}

function writeDB(data) {
    if (!fs.existsSync(DB_DIR)) {
        fs.mkdirSync(DB_DIR, { recursive: true });
    }
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Lấy IP chuẩn của client
function getClientIP(req) {
    const xForwardedFor = req.headers['x-forwarded-for'];
    if (xForwardedFor) return xForwardedFor.split(',')[0].trim();
    return req.socket.remoteAddress || 'Unknown IP';
}

// Lớp khiên bảo vệ thông minh (Bỏ qua localhost/admin, không bao giờ tự ban nhầm)
function securityShield(req, res, next) {
    const clientIP = getClientIP(req);
    
    // Bỏ qua không bao giờ chặn localhost hoặc IP nội bộ
    if (clientIP === '127.0.0.1' || clientIP === '::1' || clientIP.startsWith('::ffff:127.0.0.1')) {
        return next();
    }

    const db = readDB();
    if (db.blacklist && db.blacklist.includes(clientIP)) {
        return res.status(403).json({ 
            success: false, 
            message: 'Truy cập bị từ chối vĩnh viễn do hành vi xâm nhập hệ thống!' 
        });
    }
    next();
}

app.use(securityShield);

// Ghi log và tự động ban kẻ tấn công (Tránh tuyệt đối việc tự ban localhost)
function banAttacker(req, reason) {
    const clientIP = getClientIP(req);
    
    if (clientIP === '127.0.0.1' || clientIP === '::1' || clientIP.startsWith('::ffff:127.0.0.1')) {
        console.log(`[SECURITY NOTICE] Bỏ qua ban localhost: ${reason}`);
        return;
    }

    const userAgent = req.headers['user-agent'] || 'Unknown UA';
    const db = readDB();

    if (!db.blacklist.includes(clientIP)) {
        db.blacklist.push(clientIP);
    }

    db.logs.push({
        ip: clientIP,
        userAgent: userAgent,
        time: new Date().toLocaleString(),
        path: req.originalUrl,
        reason: reason
    });

    writeDB(db);
    console.log(`[SECURITY ALERT] Đã BAN vĩnh viễn IP: ${clientIP} | Lý do: ${reason}`);
}

// Middleware xác thực JWT Token
function verifyToken(req, res, next) {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ success: false, message: 'Chưa xác thực phiên đăng nhập!' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ success: false, message: 'Phiên đăng nhập không hợp lệ!' });
    }
}

// Middleware kiểm tra quyền Quản trị viên
function verifyAdmin(req, res, next) {
    verifyToken(req, res, () => {
        if (req.user.role !== 'admin') {
            banAttacker(req, 'User thường cố tình gọi API Admin');
            return res.status(403).json({ success: false, message: 'Từ chối quyền truy cập!' });
        }
        next();
    });
}

// ==================== CÁC API HỆ THỐNG ====================

// 1. Lấy danh sách sản phẩm
app.get('/api/products', (req, res) => {
    const db = readDB();
    res.json({ success: true, prods: db.prods });
});

// 2. Đăng nhập hệ thống
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

// 3. Lấy thông tin user hiện tại
app.get('/api/me', verifyToken, (req, res) => {
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy tài khoản' });
    res.json({ success: true, user: { username: user.username, role: user.role, balance: user.balance, is2FAEnabled: user.is2FAEnabled } });
});

// 4. Đăng xuất
app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true, message: 'Đăng xuất thành công' });
});

// 5. Mua hàng
app.post('/api/buy', verifyToken, (req, res) => {
    const { productId } = req.body;
    const db = readDB();
    
    const user = db.accs.find(x => x.username === req.user.username);
    const product = db.prods.find(p => p.id === productId);

    if (!product) return res.json({ success: false, message: 'Sản phẩm không tồn tại!' });
    if (user.balance < product.price) {
        return res.json({ success: false, message: 'Số dư tài khoản không đủ để mua sản phẩm này!' });
    }

    user.balance -= product.price;
    db.history.push({
        username: user.username,
        productName: product.name,
        price: product.price,
        time: new Date().toLocaleString()
    });

    writeDB(db);
    res.json({ success: true, message: `Mua thành công sản phẩm: ${product.name}`, newBalance: user.balance });
});

// ==================== API QUẢN TRỊ ADMIN ====================

app.post('/api/admin/add-product', verifyAdmin, (req, res) => {
    const { name, price, stock } = req.body;
    if (!name || !price) return res.json({ success: false, message: 'Thiếu thông tin sản phẩm!' });

    const db = readDB();
    db.prods.push({ id: Date.now().toString(), name, price: Number(price), stock: stock || 'Có sẵn' });
    writeDB(db);
    res.json({ success: true, message: 'Thêm sản phẩm thành công!' });
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`Server MinhAnh Store đang chạy an toàn tại cổng ${PORT}`);
});
