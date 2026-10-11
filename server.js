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
            deposits: [],
            history: [], 
            transactions: [],
            logs: [] 
        };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
    }
    
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!data.logs) data.logs = [];
    if (!data.prods) data.prods = [];
    if (!data.accs) data.accs = [];
    if (!data.coupons) data.coupons = [];
    if (!data.deposits) data.deposits = [];
    if (!data.transactions) data.transactions = [];
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
        if (req.user.username !== 'admin' || req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Từ chối quyền truy cập!' });
        }
        next();
    });
}

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

app.get('/api/me', verifyToken, (req, res) => {
    const db = readDB();
    const user = db.accs.find(x => x.username === req.user.username);
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy' });
    
    const userHistory = db.history.filter(h => h.username === user.username);
    const userDeposits = db.deposits.filter(d => d.username === user.username);
    const userTransactions = db.transactions ? db.transactions.filter(t => t.username === user.username) : [];
    const rank = getMembershipRank(user.totalDeposited || 0);

    res.json({ 
        success: true, 
        user: { 
            username: user.username, 
            role: user.role, 
            balance: user.balance, 
            totalDeposited: user.totalDeposited || 0,
            rank: rank,
            is2FAEnabled: user.is2FAEnabled,
            history: userHistory,
            deposits: userDeposits,
            transactions: userTransactions
        } 
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true, message: 'Đăng xuất thành công' });
});

app.post('/api/deposit-request', verifyToken, (req, res) => {
    const { amount } = req.body;
    const depositAmount = Number(amount);
    if (!depositAmount || depositAmount <= 0) {
        return res.json({ success: false, message: 'Số tiền không hợp lệ!' });
    }

    const db = readDB();
    if (!db.deposits) db.deposits = [];
    const depositId = 'DEP_' + Date.now();
    
    db.deposits.push({
        id: depositId,
        username: req.user.username,
        amount: depositAmount,
        status: 'Chờ duyệt',
        time: new Date().toLocaleString()
    });

    writeDB(db);
    res.json({ success: true, message: `Đã gửi yêu cầu nạp ${depositAmount.toLocaleString()}đ! Vui lòng chờ Admin duyệt tay.` });
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

    user.balance -= finalPrice;
    
    if (!db.history) db.history = [];
    db.history.push({ 
        username: user.username, 
        productName: product.name, 
        price: finalPrice, 
        vipRankApplied: rank.name,
        time: new Date().toLocaleString() 
    });

    if (!db.transactions) db.transactions = [];
    db.transactions.push({
        username: user.username,
        type: 'Mua hàng',
        amount: -finalPrice,
        description: `Mua sản phẩm: ${product.name}`,
        time: new Date().toLocaleString()
    });

    writeDB(db);

    res.json({ success: true, message: `Mua thành công ${product.name}! Đã trừ ${finalPrice.toLocaleString()}đ`, newBalance: user.balance });
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

// ==================== API QUẢN TRỊ ADMIN ====================
app.get('/api/admin/data', verifyAdmin, (req, res) => {
    const db = readDB();
    const safeUsers = db.accs.map(u => ({ username: u.username, role: u.role, balance: u.balance, totalDeposited: u.totalDeposited || 0, is2FAEnabled: u.is2FAEnabled }));
    res.json({ 
        success: true, 
        users: safeUsers, 
        prods: db.prods, 
        coupons: db.coupons, 
        banner: db.banner,
        deposits: db.deposits || []
    });
});

app.post('/api/admin/approve-deposit', verifyAdmin, (req, res) => {
    const { depositId } = req.body;
    const db = readDB();
    if (!db.deposits) return res.json({ success: false, message: 'Không tìm thấy danh sách nạp tiền!' });

    const dep = db.deposits.find(d => d.id === depositId);
    if (!dep || dep.status === 'Đã duyệt') return res.json({ success: false, message: 'Yêu cầu không hợp lệ hoặc đã được duyệt trước đó!' });

    const user = db.accs.find(u => u.username === dep.username);
    if (!user) return res.json({ success: false, message: 'Tài khoản người dùng không tồn tại!' });

    user.balance += dep.amount;
    user.totalDeposited = (user.totalDeposited || 0) + dep.amount;
    dep.status = 'Đã duyệt';

    if (!db.transactions) db.transactions = [];
    db.transactions.push({
        username: user.username,
        type: 'Nạp tiền',
        amount: dep.amount,
        description: `Nạp tiền qua QR (Admin duyệt)`,
        time: new Date().toLocaleString()
    });

    writeDB(db);
    res.json({ success: true, message: `Đã duyệt và cộng ${dep.amount.toLocaleString()}đ thành công cho @${user.username}!` });
});

app.post('/api/admin/reject-deposit', verifyAdmin, (req, res) => {
    const { depositId } = req.body;
    const db = readDB();
    if (!db.deposits) return res.json({ success: false, message: 'Không tìm thấy dữ liệu!' });

    const dep = db.deposits.find(d => d.id === depositId);
    if (dep) dep.status = 'Đã hủy';
    writeDB(db);
    res.json({ success: true, message: 'Đã từ chối yêu cầu nạp tiền!' });
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
    res.json({ success: true, message: `Đã tạo tài khoản @${username}!` });
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

app.post('/api/admin/edit-product', verifyAdmin, (req, res) => {
    const { id, name, price } = req.body;
    if (!id || !name || !price) return res.json({ success: false, message: 'Thiếu thông tin chỉnh sửa!' });
    const db = readDB();
    const product = db.prods.find(p => p.id === id);
    if (!product) return res.json({ success: false, message: 'Không tìm thấy sản phẩm!' });

    product.name = name;
    product.price = Number(price);
    writeDB(db);
    res.json({ success: true, message: 'Cập nhật sản phẩm thành công!' });
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

// ==================== TÍCH HỢP SECURITY WATCH (5s QUÉT CODE) ====================
const TELEGRAM_BOT_TOKEN = "8970111157:AAEviVkbfVBy5_0XttOGU_QFagz1LLRsPM0";
const YOUR_CHAT_ID = "8774402952";
const TARGET_DIR = __dirname;
const fileStates = new Map();

function getFileStates() {
    const states = new Map();
    function walk(dir) {
        const files = fs.readdirSync(dir);
        for (const file of files) {
            const fullPath = path.join(dir, file);
            if (fullPath.includes('node_modules') || fullPath.includes('.git') || fullPath.includes('shop.db')) continue;
            
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
    req.on('error', (error) => {
        console.error('Lỗi gửi cảnh báo:', error);
    });
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
    } catch (err) {
        console.error("Lỗi quét hệ thống:", err);
    }
}, 5000);
// ==============================================================================

app.listen(PORT, () => {
    console.log(`Server chạy an toàn và hệ thống giám sát 5s đã khởi động tại cổng ${PORT}`);
});
