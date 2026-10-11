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

// Chỉ cho phép truy cập giao diện tĩnh trong thư mục public/
app.use(express.static(path.join(__dirname, 'public')));

const DB_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DB_DIR, 'database.json');

// Khởi tạo database an toàn
function readDB() {
    if (!fs.existsSync(DB_DIR)) {
        fs.mkdirSync(DB_DIR, { recursive: true });
    }
    if (!fs.existsSync(DB_FILE)) {
        // Mật khẩu mặc định của admin là: admin123 (đã được hash bằng bcryptjs)
        const hashedPassword = bcrypt.hashSync('admin123', 10);
        const initialData = { 
            accs: [{ 
                username: 'admin', 
                password: hashedPassword, 
                role: 'admin', 
                balance: 1000000, 
                is2FAEnabled: false, 
                secret2fa: null 
            }], 
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

// Lấy IP chuẩn của client
function getClientIP(req) {
    const xForwardedFor = req.headers['x-forwarded-for'];
    if (xForwardedFor) {
        return xForwardedFor.split(',')[0].trim();
    }
    return req.socket.remoteAddress || 'Unknown IP';
}

// Khiên tự động chặn IP độc hại (Auto-Ban)
function securityShield(req, res, next) {
    const clientIP = getClientIP(req);
    const db = readDB();

    if (db.blacklist.includes(clientIP)) {
        return res.status(403).json({ 
            success: false, 
            message: 'Truy cập bị từ chối vĩnh viễn do hành vi xâm nhập hệ thống!' 
        });
    }
    next();
}

app.use(securityShield);

// Ghi log và ban IP kẻ tấn công
function banAttacker(req, reason) {
    const clientIP = getClientIP(req);
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
        banAttacker(req, 'Truy cập tài nguyên bảo mật không có Token');
        return res.status(401).json({ success: false, message: 'Chưa xác thực phiên đăng nhập!' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        banAttacker(req, 'Sử dụng Token giả mạo hoặc hết hạn');
        return res.status(403).json({ success: false, message: 'Phiên đăng nhập không hợp lệ!' });
    }
}

// Middleware kiểm tra quyền Quản trị viên
function verifyAdmin(req, res, next) {
    verifyToken(req, res, () => {
        if (req.user.role !== 'admin') {
            banAttacker(req, 'Tài khoản thường cố tình gọi API Admin');
            return res.status(403).json({ success: false, message: 'Từ chối truy cập! Yêu cầu quyền quản trị viên.' });
        }
        next();
    });
}

// ==================== CÁC API XỬ LÝ AUTHENTICATION & 2FA ====================

// 1. Đăng nhập (Hỗ trợ kiểm tra Google Authenticator nếu đã bật)
app.post('/api/login', async (req, res) => {
    const { username, password, otpToken } = req.body;
    const db = readDB();
    const user = db.accs.find(x => x.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.json({ success: false, message: 'Sai tên đăng nhập hoặc mật khẩu!' });
    }

    // Nếu tài khoản đã bật Google Authenticator
    if (user.is2FAEnabled) {
        if (!otpToken) {
            return res.json({ require2FA: true, message: 'Tài khoản yêu cầu mã Google Authenticator!' });
        }
        const verified = speakeasy.totp.verify({
            secret: user.secret2fa,
            encoding: 'base32',
            token: otpToken,
            window: 1
        });
        if (!verified) {
            return res.json({ success: false, message: 'Mã Google Authenticator không chính xác hoặc hết hạn!' });
        }
    }

    // Tạo JWT Token lưu vào HttpOnly Cookie
    const token = jwt.sign(
        { username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
    );

    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
    
    res.json({
        success: true,
        user: {
            username: user.username,
            role: user.role,
            balance: user.balance,
            is2FAEnabled: user.is2FAEnabled
        }
    });
});

// 2. Tạo mã QR để cài đặt Google Authenticator cho tài khoản
app.post('/api/2fa/setup', verifyToken, async (req, res) => {
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy tài khoản' });

    // Tạo secret mới dạng Base32
    const secret = speakeasy.generateSecret({ name: `MinhAnhStore (${user.username})` });
    user.tempSecret = secret.base32; // Lưu tạm chờ xác nhận
    writeDB(db);

    // Xuất ra mã QR để quét bằng app Google Authenticator hoặc Authy
    QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
        if (err) return res.status(500).json({ success: false, message: 'Không thể tạo mã QR 2FA' });
        res.json({ success: true, qrCodeUrl: data_url, secret: secret.base32 });
    });
});

// 3. Xác nhận và kích hoạt Google Authenticator vĩnh viễn
app.post('/api/2fa/verify', verifyToken, (req, res) => {
    const { otpToken } = req.body;
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);

    if (!user || !user.tempSecret) {
        return res.json({ success: false, message: 'Chưa khởi tạo 2FA!' });
    }

    const verified = speakeasy.totp.verify({
        secret: user.tempSecret,
        encoding: 'base32',
        token: otpToken,
        window: 1
    });

    if (verified) {
        user.secret2fa = user.tempSecret;
        user.is2FAEnabled = true;
        delete user.tempSecret;
        writeDB(db);
        return res.json({ success: true, message: 'Kích hoạt Google Authenticator thành công!' });
    } else {
        return res.json({ success: false, message: 'Mã xác thực không chính xác!' });
    }
});

// Lấy thông tin phiên đăng nhập
app.get('/api/me', verifyToken, (req, res) => {
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy tài khoản' });

    res.json({
        success: true,
        user: {
            username: user.username,
            role: user.role,
            balance: user.balance,
            is2FAEnabled: user.is2FAEnabled
        }
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true, message: 'Đăng xuất thành công' });
});

// ==================== CÁC API QUẢN TRỊ BẢO MẬT ====================
app.post('/api/admin/add-product', verifyAdmin, (req, res) => {
    const { name, price, stock } = req.body;
    if (!name || !price) return res.json({ success: false, message: 'Thiếu thông tin sản phẩm!' });

    const db = readDB();
    db.prods.push({
        id: Date.now().toString(),
        name,
        price: Number(price),
        stock: stock || ''
    });
    writeDB(db);
    res.json({ success: true, message: 'Thêm sản phẩm thành công!' });
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`Server MinhAnh Store đang chạy cực kỳ bảo mật với Google Authenticator tại cổng ${PORT}`);
});
