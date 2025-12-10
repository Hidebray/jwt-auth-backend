// src/index.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

// --- Middlewares ---
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:5173', // Cho phép Frontend Vite gọi vào
  credentials: true
}));

// --- Test Route (Để kiểm tra server có sống không) ---
app.get('/', (req, res) => {
  res.send('✅ Server Backend đang chạy ổn định!');
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`\n🚀 Server đang chạy tại: http://localhost:${PORT}`);
  console.log(`👉 Thử truy cập: http://localhost:${PORT}/`);
});

// --- MOCK DATABASE (Dữ liệu giả lập) ---
const users = [
  { id: '1', username: 'demo', password: 'password', email: 'demo@example.com', role: 'admin' },
  { id: '2', username: 'user', password: 'password', email: 'user@example.com', role: 'user' }
];

let refreshTokens = []; // Lưu danh sách Refresh Token hợp lệ (Whitelist)

// --- CONSTANTS ---
const ACCESS_TOKEN_SECRET = 'secret_key_access_123';
const REFRESH_TOKEN_SECRET = 'secret_key_refresh_456';

// --- HELPER FUNCTIONS ---
const generateAccessToken = (user) => {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role }, 
    ACCESS_TOKEN_SECRET, 
    { expiresIn: '15s' } // Hết hạn sau 15 giây để test chức năng auto-refresh
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user.id, username: user.username }, 
    REFRESH_TOKEN_SECRET, 
    { expiresIn: '7d' }
  );
};

// --- API ROUTES ---

// 1. Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);

  if (!user) return res.status(401).json({ message: 'Sai tên đăng nhập hoặc mật khẩu' });

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  refreshTokens.push(refreshToken);

  res.json({
    user: { id: user.id, username: user.username, email: user.email, role: user.role },
    accessToken,
    refreshToken
  });
});

// 2. Refresh Token (Endpoint quan trọng nhất)
app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ message: 'Thiếu Refresh Token' });
  if (!refreshTokens.includes(refreshToken)) return res.status(403).json({ message: 'Refresh Token không hợp lệ' });

  jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Refresh Token hết hạn' });

    // Xóa token cũ, tạo token mới (Token Rotation)
    refreshTokens = refreshTokens.filter(t => t !== refreshToken);
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);
    refreshTokens.push(newRefreshToken);

    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  });
});

// 3. Logout
app.post('/api/auth/logout', (req, res) => {
  const { refreshToken } = req.body;
  refreshTokens = refreshTokens.filter(t => t !== refreshToken);
  res.sendStatus(204);
});

// 4. Protected Route (Lấy thông tin User)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(401); // Token hết hạn -> Frontend sẽ bắt lỗi này để refresh
    req.user = user;
    next();
  });
};

app.get('/api/user/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.sendStatus(404);
  res.json(user);
});

// Start Server
app.listen(PORT, () => console.log(`Backend đang chạy tại http://localhost:${PORT}`));