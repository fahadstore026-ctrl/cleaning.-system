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
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production';

// إعدادات عامة
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// ✅ اتصال PostgreSQL - نسخة صارمة تمنع الاتصال بـ localhost
const pool = (() => {
  const dbUrl = process.env.DATABASE_URL;
  
  if (!dbUrl || dbUrl.trim() === '') {
    console.error('🚨 خطأ حرج: متغير DATABASE_URL غير موجود أو فارغ!');
    console.error('💡 تأكد من ربط cleaning-db بالتطبيق في Railway Variables.');
    console.error('🔗 اضغط على cleaning-system → Variables → Add Variable → اختر cleaning-db');
    process.exit(1); // يوقف التشغيل فوراً لتظهر الرسالة في Logs بوضوح
  }

  console.log('✅ تم العثور على DATABASE_URL بنجاح');
  console.log('🔍 جاري الاتصال بقاعدة البيانات...');
  
  return new Pool({
    connectionString: dbUrl,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });
})();

// 🔧 إنشاء الجداول عند البدء
async function initDB() {
  try {
    await pool.query('SELECT NOW()'); // اختبار الاتصال
    console.log('✅ اتصال قاعدة البيانات ناجح!');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'emp')),
        name_ar TEXT NOT NULL,
        name_en TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('📦 جدول users جاهز');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS zones (
        id TEXT PRIMARY KEY,
        name_ar TEXT NOT NULL,
        name_en TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('📦 جدول zones جاهز');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS logs (
        id TEXT PRIMARY KEY,
        zone_id TEXT REFERENCES zones(id) ON DELETE CASCADE,
        emp_id TEXT REFERENCES users(id) ON DELETE CASCADE,
        status TEXT NOT NULL CHECK (status IN ('ممتاز', 'يحتاج تحسين', 'غير مقبول')),
        notes TEXT,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        edited BOOLEAN DEFAULT FALSE
      )
    `);
    console.log('📦 جدول logs جاهز');
    
    console.log('✅ جميع الجداول تم إنشاؤها بنجاح');
    
  } catch (err) {
    console.error('❌ خطأ في تهيئة قاعدة البيانات:', err.message);
    console.error('🔍 تأكد من أن DATABASE_URL صحيح ويمكن الوصول للقاعدة');
  }
}

// 👤 إنشاء مدير افتراضي
async function createDefaultAdmin() {
  try {
    // ننتظر قليلاً لضمان اكتمال initDB
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const { rows } = await pool.query('SELECT COUNT(*) FROM users');
    const count = parseInt(rows[0].count);
    
    console.log(`📊 عدد المستخدمين الحالي في القاعدة: ${count}`);
    
    if (count === 0) {
      const hash = await bcrypt.hash('admin123', 10);
      await pool.query(
        "INSERT INTO users (id, password, role, name_ar, name_en) VALUES ($1, $2, 'admin', 'المدير', 'Admin')",
        ['admin', hash]
      );
      console.log('✅✅✅ تم إنشاء مدير افتراضي بنجاح!');
      console.log('👤 المستخدم: admin');
      console.log('🔑 كلمة المرور: admin123');
      console.log('=================================');
    }
  } catch (err) {
    console.error('❌ خطأ في إنشاء المدير:', err.message);
  }
}

// تشغيل الدوال عند البدء
initDB().then(() => createDefaultAdmin());

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

// 📡 مسارات API
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    console.log(`🔐 محاولة تسجيل دخول للمستخدم: ${username}`);
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [username.toLowerCase()]);
    if (!rows[0]) {
      console.log('❌ المستخدم غير موجود');
      return res.status(401).json({ error: 'بيانات غير صحيحة' });
    }
    const valid = await bcrypt.compare(password, rows[0].password);
    if (!valid) {
      console.log('❌ كلمة المرور غير صحيحة');
      return res.status(401).json({ error: 'بيانات غير صحيحة' });
    }
    const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, JWT_SECRET, { expiresIn: '24h' });
    console.log(`✅ نجاح تسجيل دخول: ${username} (${rows[0].role})`);
    res.json({
      token,
      user: { id: rows[0].id, role: rows[0].role, name_ar: rows[0].name_ar, name_en: rows[0].name_en }
    });
  } catch (err) {
    console.error('❌ خطأ في تسجيل الدخول:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/zones', authenticate, async (_, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM zones ORDER BY id');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/zones', authenticate, async (req, res) => {
  const { id, name_ar, name_en } = req.body;
  try {
    await pool.query('INSERT INTO zones (id, name_ar, name_en) VALUES ($1, $2, $3)', [id, name_ar, name_en]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/zones/:id', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM zones WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/employees', authenticate, async (_, res) => {
  try {
    const { rows } = await pool.query("SELECT id, role, name_ar, name_en, created_at FROM users WHERE role='emp'");
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/employees', authenticate, async (req, res) => {
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

app.put('/api/employees/:id', authenticate, async (req, res) => {
  const { name_ar, name_en, password } = req.body;
  if (!name_ar || !name_en) return res.status(400).json({ error: 'حقول ناقصة' });
  try {
    let sql = "UPDATE users SET name_ar=$1, name_en=$2";
    let params = [name_ar, name_en];
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      sql += ", password=$3";
      params.push(hash);
    }
    sql += " WHERE id=$" + (params.length + 1);
    params.push(req.params.id);
    await pool.query(sql, params);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/employees/:id', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/logs', authenticate, async (_, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT l.*, z.name_ar, z.name_en, u.name_ar as emp_name_ar, u.name_en as emp_name_en 
      FROM logs l 
      JOIN zones z ON l.zone_id=z.id 
      JOIN users u ON l.emp_id=u.id 
      ORDER BY l.ts DESC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logs', authenticate, async (req, res) => {
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

app.put('/api/logs/:id', authenticate, async (req, res) => {
  const { date, time, notes } = req.body;
  try {
    await pool.query(
      "UPDATE logs SET date=$1, time=$2, notes=$3, edited=true WHERE id=$4",
      [date, time, notes || '-', req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/logs/:id', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM logs WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// خدمة الواجهة الأمامية
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// بدء الخادم
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 الخادم يعمل على المنفذ ${PORT}`);
  console.log(`🌐 الرابط المحلي: http://localhost:${PORT}`);
});
