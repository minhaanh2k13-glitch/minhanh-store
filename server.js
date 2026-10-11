const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const https = require('https');

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
                { username: 'admin', password: hashedPassword, role: 'admin', balance: 1000000, totalDeposited: 1000000, twoFactorEnabled: false, secret2fa: null, vip: 'gold' }
            ], 
            prods: [
                { id: '1', name: 'Tài khoản Netflix Premium 1 Tháng', price: 69000, stock: 'Acc1:pass1\nAcc2:pass2' },
                { id: '2', name: 'Key Windows 11 Pro Bản Quyền Vĩnh Viễn', price: 150000, stock: 'KEY1-KEY2\nKEY3-KEY4' }
            ], 
            coupons: [
                { code: 'MINHANH2K', rate: 10, expiry: '2030-12-31T23:59' }
            ],
            banner: '👻 HALLOWEEN FLASH SALE: Nhập mã "MINHANH2K" giảm ngay 10% tổng đơn hàng ma quái! 🦇',
            pending_deposits: [],
            history: [], 
            txs: [],
            logs: [] 
        };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
    }
    
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!data.logs) data.logs = [];
    if (!data.prods) data.prods = [];
    if (!data.accs) data.accs = [];
    if (!data.coupons) data.coupons = [];
    if (!data.pending_deposits) data.pending_deposits = [];
    if (!data.txs) data.txs = [];
    if (!data.banner) data.banner = 'Chào mừng đến với Anh Store!';
    if (!data.history) data.history = [];
    return data;
}

function writeDB(data) {
    if (!fs.existsSync(DB_DIR)) {
        fs.mkdirSync(DB_DIR, { recursive: true });
    }
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// API CƠ SỞ DỮ LIỆU
app.get('/api/db/:key', (req, res) => {
    const db = readDB();
    const key = req.params.key;
    res.json({ success: true, data: db[key] || [] });
});

app.post('/api/login', async (req, res) => {
    const { username, password, otpToken } = req.body;
    const db = readDB();
    const user = db.accs.find(x => x.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.json({ success: false, message: 'Sai tên đăng nhập hoặc mật khẩu!' });
    }

    if (user.twoFactorEnabled) {
        if (!otpToken) return res.json({ require2FA: true, message: 'Yêu cầu mã Google Authenticator!' });
        const verified = speakeasy.totp.verify({ secret: user.secret2fa, encoding: 'base32', token: otpToken, window: 1 });
        if (!verified) return res.json({ success: false, message: 'Mã Google Authenticator không chính xác!' });
    }

    res.json({ success: true, user: { username: user.username, role: user.role, balance: user.balance, vip: user.vip || 'free', twoFactorEnabled: user.twoFactorEnabled } });
});

app.post('/api/2fa/setup', async (req, res) => {
    const { username } = req.body;
    const db = readDB();
    const user = db.accs.find(x => x.username === username);
    if (!user) return res.json({ success: false, message: 'Không tìm thấy tài khoản' });

    const secret = speakeasy.generateSecret({ name: `AnhStore (${user.username})` });
    user.tempSecret = secret.base32;
    writeDB(db);
    QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
        if (err) return res.status(500).json({ success: false, message: 'Lỗi tạo QR' });
        res.json({ success: true, qrCodeUrl: data_url });
    });
});

app.post('/api/2fa/verify', (req, res) => {
    const { username, token } = req.body;
    const db = readDB();
    const user = db.accs.find(x => x.username === username);
    if (!user || !user.tempSecret) return res.json({ success: false, message: 'Chưa khởi tạo 2FA' });

    const verified = speakeasy.totp.verify({ secret: user.tempSecret, encoding: 'base32', token, window: 1 });
    if (verified) {
        user.secret2fa = user.tempSecret;
        user.twoFactorEnabled = true;
        delete user.tempSecret;
        writeDB(db);
        return res.json({ success: true, message: 'Bật 2FA thành công!' });
    }
    res.json({ success: false, message: 'Mã OTP không chính xác!' });
});

app.post('/api/deposit/submit', (req, res) => {
    const { username, amount } = req.body;
    const amt = Number(amount);
    if (!amt || amt <= 0) return res.json({ success: false, message: 'Số tiền không hợp lệ!' });

    const db = readDB();
    db.pending_deposits.push({
        username,
        amount: amt,
        time: new Date().toLocaleString()
    });
    writeDB(db);
    res.json({ success: true });
});

// ==================== QUẢN TRỊ ADMIN ====================
app.post('/api/admin/edit-balance', (req, res) => {
    const { adminUsername, targetUsername, amount, type } = req.body;
    const db = readDB();
    const admin = db.accs.find(x => x.username === adminUsername && x.role === 'admin');
    if (!admin) return res.json({ success: false, message: 'Không có quyền quản trị!' });

    const target = db.accs.find(x => x.username === targetUsername);
    if (!target) return res.json({ success: false, message: 'Tài khoản đích không tồn tại!' });

    target.balance = (target.balance || 0) + Number(amount);
    db.txs.push({
        username: targetUsername,
        desc: 'Admin nạp tiền trực tiếp',
        amount: Number(amount),
        time: new Date().toLocaleString()
    });
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/admin/delete-user', (req, res) => {
    const { adminUsername, targetUsername } = req.body;
    const db = readDB();
    const admin = db.accs.find(x => x.username === adminUsername && x.role === 'admin');
    if (!admin) return res.json({ success: false, message: 'Không có quyền!' });
    if (targetUsername === 'admin') return res.json({ success: false, message: 'Không thể ban tài khoản Root Admin!' });

    db.accs = db.accs.filter(x => x.username !== targetUsername);
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/admin/create-user', (req, res) => {
    const { adminUsername, newUsername, newPassword } = req.body;
    const db = readDB();
    const admin = db.accs.find(x => x.username === adminUsername && x.role === 'admin');
    if (!admin) return res.json({ success: false, message: 'Không có quyền!' });

    if (db.accs.find(x => x.username === newUsername)) return res.json({ success: false, message: 'Tài khoản đã tồn tại!' });

    db.accs.push({
        username: newUsername,
        password: bcrypt.hashSync(newPassword, 10),
        role: 'user',
        balance: 0,
        vip: 'free',
        twoFactorEnabled: false
    });
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/admin/approve-deposit', (req, res) => {
    const { adminUsername, index } = req.body;
    const db = readDB();
    const admin = db.accs.find(x => x.username === adminUsername && x.role === 'admin');
    if (!admin) return res.json({ success: false, message: 'Không có quyền!' });

    let dep = db.pending_deposits[index];
    if (!dep) return res.json({ success: false, message: 'Yêu cầu không tồn tại' });

    let user = db.accs.find(x => x.username === dep.username);
    if (user) {
        user.balance = (user.balance || 0) + dep.amount;
        db.txs.push({
            username: dep.username,
            desc: 'Nạp tiền qua QR (Đã duyệt)',
            amount: dep.amount,
            time: new Date().toLocaleString()
        });
    }

    db.pending_deposits.splice(index, 1);
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/admin/reject-deposit', (req, res) => {
    const { adminUsername, index } = req.body;
    const db = readDB();
    const admin = db.accs.find(x => x.username === adminUsername && x.role === 'admin');
    if (!admin) return res.json({ success: false, message: 'Không có quyền!' });

    db.pending_deposits.splice(index, 1);
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/admin/add-product', (req, res) => {
    const { adminUsername, name, price, stock } = req.body;
    const db = readDB();
    const admin = db.accs.find(x => x.username === adminUsername && x.role === 'admin');
    if (!admin) return res.json({ success: false, message: 'Không có quyền!' });

    db.prods.push({
        id: Date.now().toString(),
        name,
        price: Number(price),
        stock
    });
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/admin/delete-product', (req, res) => {
    const { adminUsername, index } = req.body;
    const db = readDB();
    const admin = db.accs.find(x => x.username === adminUsername && x.role === 'admin');
    if (!admin) return res.json({ success: false, message: 'Không có quyền!' });

    db.prods.splice(index, 1);
    writeDB(db);
    res.json({ success: true });
});

// ==================== BẢO MẬT GỬI TELEGRAM ====================
const TELEGRAM_BOT_TOKEN = "8970111157:AAG4BQvnCwF-LuzLEqFt_-znNANR_sx07Ao";
const YOUR_CHAT_ID = "8774402952";
const TARGET_DIR = __dirname;

function getFileStates() {
    const states = new Map();
    function walk(dir) {
        const files = fs.readdirSync(dir);
        for (const file of files) {
            const fullPath = path.join(dir, file);
            if (fullPath.includes('node_modules') || fullPath.includes('.git') || fullPath.includes('database.json')) continue;
            
            const stats = fs.statSync(fullPath);
            if (stats.isDirectory()) {
                walk(fullPath);
            } else {
                states.set(fullPath, stats.mtimeMs);
            }
        }
    }
    walk(TARGET_DIR);
    return states;
}

function sendSecurityAlert(message) {
    const data = JSON.stringify({
        chat_id: YOUR_CHAT_ID,
        text: `🚨 CẢNH BÁO AN NINH HỆ THỐNG!\n\n${message}`
    });

    const options = {
        hostname: 'api.telegram.org',
        port: 443,
        path: `/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': data.length
        }
    };

    const req = https.request(options, (res) => {});
    req.on('error', (error) => {});
    req.write(data);
    req.end();
}

const initialStates = getFileStates();

setInterval(() => {
    try {
        const currentStates = getFileStates();
        for (let [file, mtime] of currentStates.entries()) {
            if (!initialStates.has(file)) {
                sendSecurityAlert(`📁 Phát hiện file mới được tạo / tải lên:\n${file}`);
                initialStates.set(file, mtime);
            } else if (initialStates.get(file) !== mtime) {
                sendSecurityAlert(`⚠️ Phát hiện file mã nguồn vừa bị chỉnh sửa:\n${file}`);
                initialStates.set(file, mtime);
            }
        }
    } catch (err) {}
}, 5000);

app.listen(PORT, () => {
    console.log(`Server running securely on port ${PORT}`);
});
