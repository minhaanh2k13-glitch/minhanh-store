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
                { username: 'admin', password: hashedPassword, role: 'admin', balance: 1000000, totalDeposited: 1000000, is2FAEnabled: false, secret2fa: null }
            ], 
            prods: [
                { id: '1', name: 'Tài khoản Netflix Premium 1 Tháng', price: 69000, stock: 'Có sẵn' },
                { id: '2', name: 'Key Windows 11 Pro Bản Quyền Vĩnh Viễn', price: 150000, stock: 'Có sẵn' }
            ], 
            coupons: [
                { code: 'MINHANH2K', discountPercent: 10 }
            ],
            banner: 'Mã giảm giá "MINHANH2K" giảm ngay 10% tổng đơn hàng! 🔒',
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
    if (!data.accs) data.accs = [];
    if (!data.coupons) data.coupons = [];
    if (!data.banner) data.banner = 'Chào mừng đến với MinhAnh Store!';
    if (!data.history) data.history = [];
    
    data.accs.forEach(u => {
        if (u.totalDeposited === undefined) u.totalDeposited = u.balance || 0;
    });

    return data;
}

function writeDB(data) {
    if (!fs.existsSync(DB_DIR)) {
        fs.mkdirSync(DB_DIR, { recursive: true });
    }
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function getMembershipRank(totalDeposited) {
    if (totalDeposited >= 100000) {
        return { name: 'Vàng 🥇', discount: 20, color: '#f59e0b' };
    } else if (totalDeposited >= 25000) {
        return { name: 'Bạc 🥈', discount: 5, color: '#38bdf8' };
    } else {
        return { name: 'Đồng (Free) 🥉', discount: 0, color: '#94a3b8' };
    }
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
        return res.status(403).json({ success: false, message: 'Truy cập bị từ chối vĩnh viễn!' });
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
            banAttacker(req, 'Cố tình truy cập trái phép API Admin!');
            return res.status(403).json({ success: false, message: 'Từ chối quyền truy cập! IP của bạn đã bị ghi nhận.' });
        }
        next();
    });
}

// Bẫy Honeypot
app.all('/api/secret-admin-trap', (req, res) => {
    banAttacker(req, 'Sa bẫy Honeypot!');
    res.status(403).json({ success: false, message: 'CẢNH BÁO: IP của bạn đã bị ban vĩnh viễn!' });
});

// ==================== API CÔNG KHAI ====================
app.get('/api/store-info', (req, res) => {
    const db = readDB();
    res.json({ success: true, prods: db.prods, banner: db.banner, coupons: db.coupons });
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

// ==================== API BẢO MẬT (USER) ====================
app.get('/api/me', verifyToken, (req, res) => {
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy' });
    
    const userHistory = db.history.filter(h => h.username === user.username);
    const rank = getMembershipRank(user.totalDeposited || 0);

    // CHỈ TRẢ VỀ DỮ LIỆU CỦA CHÍNH USER ĐÓ, TUYỆT ĐỐI KHÔNG LỘ USER KHÁC
    res.json({ 
        success: true, 
        user: { 
            username: user.username, 
            role: user.role, 
            balance: user.balance, 
            totalDeposited: user.totalDeposited || 0,
            rank: rank,
            is2FAEnabled: user.is2FAEnabled,
            history: userHistory
        } 
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true, message: 'Đăng xuất thành công' });
});

// Chặn tuyệt đối việc tự hack tiền: Tạm thời vô hiệu hóa hoặc yêu cầu cơ chế nạp tiền thật qua Admin/Mã thẻ cào
app.post('/api/deposit', verifyToken, (req, res) => {
    // KHÔNG CHO PHÉP TỰ NẠP ẢO NỮA - Tạm khóa hoặc yêu cầu mã nạp tiền do admin cấp
    return res.json({ success: false, message: 'Tính năng nạp tiền tự động đang bảo trì. Vui lòng liên hệ Admin để được cộng tiền!' });
});

app.post('/api/buy', verifyToken, (req, res) => {
    const { productId, couponCode } = req.body;
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);
    const product = db.prods.find(p => p.id === productId);

    if (!product) return res.json({ success: false, message: 'Sản phẩm không tồn tại!' });

    const rank = getMembershipRank(user.totalDeposited || 0);
    let finalPrice = product.price * (1 - rank.discount / 100);

    if (couponCode) {
        const coupon = db.coupons.find(c => c.code.toUpperCase() === couponCode.toUpperCase());
        if (coupon) {
            finalPrice = finalPrice * (1 - coupon.discountPercent / 100);
        } else {
            return res.json({ success: false, message: 'Mã giảm giá không hợp lệ!' });
        }
    }

    finalPrice = Math.round(finalPrice);

    if (user.balance < finalPrice) {
        return res.json({ success: false, message: `Số dư không đủ! Cần ${finalPrice.toLocaleString()}đ` });
    }

    // KIỂM TRA LẠI AN TOÀN TRƯỚC KHI TRỪ TIỀN
    user.balance -= finalPrice;
    db.history.push({ 
        username: user.username, 
        productName: product.name, 
        price: finalPrice, 
        vipRankApplied: rank.name,
        time: new Date().toLocaleString() 
    });
    writeDB(db);

    res.json({ success: true, message: `Mua thành công ${product.name}! Đã trừ ${finalPrice.toLocaleString()}đ`, newBalance: user.balance });
});

// ==================== API QUẢN TRỊ ADMIN (ĐÃ BỌC KÍN BỞI verifyAdmin) ====================
app.get('/api/admin/data', verifyAdmin, (req, res) => {
    const db = readDB();
    const safeUsers = db.accs.map(u => ({ username: u.username, role: u.role, balance: u.balance, totalDeposited: u.totalDeposited || 0, is2FAEnabled: u.is2FAEnabled }));
    res.json({ success: true, users: safeUsers, prods: db.prods, coupons: db.coupons, banner: db.banner });
});

app.post('/api/admin/create-user', verifyAdmin, (req, res) => {
    const { username, password, initialBalance } = req.body;
    if (!username || !password) return res.json({ success: false, message: 'Thiếu thông tin!' });
    const db = readDB();
    if (db.accs.find(u => u.username === username)) return res.json({ success: false, message: 'Tài khoản đã tồn tại!' });

    const initBal = Number(initialBalance) || 0;
    db.accs.push({
        username,
        password: bcrypt.hashSync(password, 10),
        role: 'user',
        balance: initBal,
        totalDeposited: initBal,
        is2FAEnabled: false,
        secret2fa: null
    });
    writeDB(db);
    res.json({ success: true, message: `Đã tạo tài khoản @${username} thành công!` });
});

app.post('/api/admin/ban-user', verifyAdmin, (req, res) => {
    const { username } = req.body;
    if (username === 'admin') return res.json({ success: false, message: 'Không thể xóa Root Admin!' });
    const db = readDB();
    db.accs = db.accs.filter(u => u.username !== username);
    writeDB(db);
    res.json({ success: true, message: `Đã BAN tài khoản @${username}!` });
});

app.post('/api/admin/add-product', verifyAdmin, (req, res) => {
    const { name, price, stock } = req.body;
    if (!name || !price) return res.json({ success: false, message: 'Thiếu thông tin!' });
    const db = readDB();
    db.prods.push({ id: Date.now().toString(), name, price: Number(price), stock: stock || 'Có sẵn' });
    writeDB(db);
    res.json({ success: true, message: 'Thêm sản phẩm thành công!' });
});

app.post('/api/admin/delete-product', verifyAdmin, (req, res) => {
    const { id } = req.body;
    const db = readDB();
    db.prods = db.prods.filter(p => p.id !== id);
    writeDB(db);
    res.json({ success: true, message: 'Đã xóa sản phẩm!' });
});

app.post('/api/admin/add-coupon', verifyAdmin, (req, res) => {
    const { code, discountPercent } = req.body;
    if (!code || !discountPercent) return res.json({ success: false, message: 'Thiếu thông tin!' });
    const db = readDB();
    db.coupons.push({ code: code.toUpperCase(), discountPercent: Number(discountPercent) });
    writeDB(db);
    res.json({ success: true, message: `Tạo mã ${code.toUpperCase()} thành công!` });
});

app.post('/api/admin/delete-coupon', verifyAdmin, (req, res) => {
    const { code } = req.body;
    const db = readDB();
    db.coupons = db.coupons.filter(c => c.code !== code);
    writeDB(db);
    res.json({ success: true, message: `Đã xóa mã ${code}!` });
});

app.post('/api/admin/update-banner', verifyAdmin, (req, res) => {
    const { bannerText } = req.body;
    const db = readDB();
    db.banner = bannerText || '';
    writeDB(db);
    res.json({ success: true, message: 'Cập nhật Banner thành công!' });
});

app.listen(PORT, () => {
    console.log(`Server chạy an toàn tại cổng ${PORT}`);
});
