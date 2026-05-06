// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'my-super-secret-jwt-key';

// ✅ إعدادات عامة
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// 🔌 اتصال قاعدة البيانات
let pool = null;

if (process.env.DATABASE_URL) {
    try {
        pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: { rejectUnauthorized: false } // مهم جداً لـ Railway
        });
        console.log('✅ تم العثور على DATABASE_URL ومحاولة الاتصال...');
    } catch (error) {
        console.error('❌ خطأ في تهيئة الاتصال:', error.message);
    }
} else {
    console.warn('⚠️ تحذير: متغير DATABASE_URL غير موجود!');
}

// 🛠️ تهيئة قاعدة البيانات (إنشاء الجداول والمدير)
async function initDB() {
    if (!pool) {
        console.error('❌ لا يمكن إنشاء الجداول لأن قاعدة البيانات غير متصلة.');
        return;
    }

    try {
        console.log('📦 التحقق من الجداول...');
        
        // جدول المستخدمين
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                name_ar TEXT NOT NULL,
                name_en TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // جدول المناطق
        await pool.query(`
            CREATE TABLE IF NOT EXISTS zones (
                id TEXT PRIMARY KEY,
                name_ar TEXT NOT NULL,
                name_en TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // جدول السجلات
        await pool.query(`
            CREATE TABLE IF NOT EXISTS logs (
                id TEXT PRIMARY KEY,
                zone_id TEXT REFERENCES zones(id) ON DELETE CASCADE,
                emp_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                status TEXT NOT NULL,
                notes TEXT,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                edited BOOLEAN DEFAULT FALSE
            )
        `);

        console.log('✅ الجداول جاهزة.');

        // ✅ إنشاء مدير افتراضي إذا كانت القاعدة فارغة
        const result = await pool.query('SELECT COUNT(*) FROM users');
        const userCount = parseInt(result.rows[0].count);

        if (userCount === 0) {
            console.log(' إنشاء المدير الافتراضي...');
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query(
                `INSERT INTO users (id, password, role, name_ar, name_en) 
                 VALUES ($1, $2, $3, $4, $5)`,
                ['admin', hashedPassword, 'admin', 'المدير', 'Admin']
            );
            console.log('✅✅✅ تم إنشاء المدير بنجاح:');
            console.log(' المستخدم: admin');
            console.log(' كلمة المرور: admin123');
        }

    } catch (error) {
        console.error('❌ خطأ أثناء تهيئة قاعدة البيانات:', error.message);
    }
}

// تشغيل التهيئة
initDB();

// 🔐 Middleware للمصادقة
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'غير مصرح' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(403).json({ error: 'توكن غير صالح' });
    }
};

//  مسارات API

// تسجيل الدخول
app.post('/api/login', async (req, res) => {
    if (!pool) return res.status(500).json({ error: 'قاعدة البيانات غير متصلة' });
    const { username, password } = req.body;
    try {
        const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [username.toLowerCase()]);
        if (!rows[0]) return res.status(401).json({ error: 'بيانات غير صحيحة' });
        
        const match = await bcrypt.compare(password, rows[0].password);
        if (!match) return res.status(401).json({ error: 'بيانات غير صحيحة' });

        const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, JWT_SECRET, { expiresIn: '24h' });
        res.json({
            token,
            user: { id: rows[0].id, role: rows[0].role, name_ar: rows[0].name_ar, name_en: rows[0].name_en }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// جلب المناطق
app.get('/api/zones', authenticate, async (_, res) => {
    if (!pool) return res.status(500).json({ error: 'DB Error' });
    try {
        const { rows } = await pool.query('SELECT * FROM zones ORDER BY id');
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// إضافة منطقة
app.post('/api/zones', authenticate, async (req, res) => {
    if (!pool) return res.status(500).json({ error: 'DB Error' });
    const { id, name_ar, name_en } = req.body;
    try {
        await pool.query('INSERT INTO zones (id, name_ar, name_en) VALUES ($1, $2, $3)', [id, name_ar, name_en]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// حذف منطقة
app.delete('/api/zones/:id', authenticate, async (req, res) => {
    if (!pool) return res.status(500).json({ error: 'DB Error' });
    try {
        await pool.query('DELETE FROM zones WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// جلب الموظفين
app.get('/api/employees', authenticate, async (_, res) => {
    if (!pool) return res.status(500).json({ error: 'DB Error' });
    try {
        const { rows } = await pool.query("SELECT id, role, name_ar, name_en FROM users WHERE role = 'emp'");
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// إضافة موظف
app.post('/api/employees', authenticate, async (req, res) => {
    if (!pool) return res.status(500).json({ error: 'DB Error' });
    const { id, name_ar, name_en, password } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (id, password, role, name_ar, name_en) VALUES ($1, $2, 'emp', $3, $4)",
            [id, hash, name_ar, name_en]
        );
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// جلب السجلات
app.get('/api/logs', authenticate, async (_, res) => {
    if (!pool) return res.status(500).json({ error: 'DB Error' });
    try {
        const { rows } = await pool.query(`
            SELECT l.*, z.name_ar, z.name_en, u.name_ar as emp_name_ar, u.name_en as emp_name_en 
            FROM logs l 
            JOIN zones z ON l.zone_id = z.id 
            JOIN users u ON l.emp_id = u.id 
            ORDER BY l.ts DESC
        `);
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// إضافة سجل
app.post('/api/logs', authenticate, async (req, res) => {
    if (!pool) return res.status(500).json({ error: 'DB Error' });
    const { zone_id, status, notes, date, time } = req.body;
    const id = `LOG-${Date.now()}`;
    try {
        await pool.query(
            `INSERT INTO logs (id, zone_id, emp_id, status, notes, date, time, edited) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, false)`,
            [id, zone_id, req.user.id, status, notes || '-', date, time]
        );
        res.json({ success: true, id });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// حذف سجل
app.delete('/api/logs/:id', authenticate, async (req, res) => {
    if (!pool) return res.status(500).json({ error: 'DB Error' });
    try {
        await pool.query('DELETE FROM logs WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// خدمة الواجهة الأمامية
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// بدء الخادم
app.listen(PORT, '0.0.0.0', () => {
    console.log(` Server running on port ${PORT}`);
});
