// server.js - Cleaning System with Full Arabic Support
require('dotenv').config();

// Set UTF-8 encoding for Arabic support
process.env.PGCLIENTENCODING = 'UTF8';

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cleaning-system-secret-2026';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Prevent caching
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

// Database connection with UTF-8
let pool = null;
if (process.env.DATABASE_URL) {
    pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
        client_encoding: 'UTF8'
    });
    
    pool.query('SET client_encoding TO UTF8', (err) => {
        if (err) console.error('UTF8 Error:', err);
        else console.log('✅ UTF-8 encoding enabled');
    });
    
    console.log('✅ Database connected');
}

// Initialize database
async function initDB() {
    if (!pool) return;
    
    try {
        await pool.query('ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check').catch(() => {});
        
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
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS zones (
                id TEXT PRIMARY KEY,
                name_ar TEXT NOT NULL,
                name_en TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS logs (
                id TEXT PRIMARY KEY,
                zone_id TEXT REFERENCES zones(id) ON DELETE CASCADE,
                emp_id TEXT,
                status TEXT NOT NULL,
                notes TEXT,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                edited BOOLEAN DEFAULT FALSE
            )
        `);
        
        const res = await pool.query('SELECT COUNT(*) FROM users');
        if (parseInt(res.rows[0].count) === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await pool.query(
                "INSERT INTO users (id, password, role, name_ar, name_en) VALUES ($1, $2, $3, $4, $5)",
                ['admin', hash, 'مدير', 'المدير', 'Admin']
            );
            console.log('✅ Admin created: admin / admin123');
        }
        
        console.log('✅ Database ready');
    } catch (e) {
        console.error('❌ DB Error:', e.message);
    }
}

initDB();

// Auth middleware
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(403).json({ error: 'Invalid token' });
    }
};

// Routes
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [username.toLowerCase().trim()]);
        
        if (!rows[0]) return res.status(401).json({ error: 'Invalid credentials' });
        
        const valid = await bcrypt.compare(password, rows[0].password);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
        
        const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, JWT_SECRET, { expiresIn: '24h' });
        
        res.json({
            token,
            user: { 
                id: rows[0].id, 
                role: rows[0].role, 
                name_ar: rows[0].name_ar, 
                name_en: rows[0].name_en 
            }
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/employees', authenticate, async (req, res) => {
    try {
        const { rows } = await pool.query("SELECT id, role, name_ar, name_en FROM users WHERE id != 'admin' ORDER BY created_at DESC");
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/employees', authenticate, async (req, res) => {
    try {
        const { id, name_ar, name_en, password, role } = req.body;
        const hash = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (id, password, role, name_ar, name_en) VALUES ($1, $2, $3, $4, $5)",
            [id, hash, role, name_ar, name_en || name_ar]
        );
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/employees/:id', authenticate, async (req, res) => {
    try {
        await pool.query('DELETE FROM logs WHERE emp_id = $1', [req.params.id]);
        await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/zones', authenticate, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM zones ORDER BY id');
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/zones', authenticate, async (req, res) => {
    try {
        const { id, name_ar, name_en } = req.body;
        await pool.query('INSERT INTO zones (id, name_ar, name_en) VALUES ($1, $2, $3)', [id, name_ar, name_en || name_ar]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/zones/:id', authenticate, async (req, res) => {
    try {
        await pool.query('DELETE FROM zones WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/logs', authenticate, async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT l.*, z.name_ar as zone_name_ar, z.name_en as zone_name_en,
                   u.name_ar as emp_name_ar, u.name_en as emp_name_en
            FROM logs l
            LEFT JOIN zones z ON l.zone_id = z.id
            LEFT JOIN users u ON l.emp_id = u.id
            ORDER BY l.ts DESC
        `);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logs', authenticate, async (req, res) => {
    try {
        const { zone_id, status, notes, date, time } = req.body;
        const id = `LOG-${Date.now()}`;
        await pool.query(
            `INSERT INTO logs (id, zone_id, emp_id, status, notes, date, time, edited)
             VALUES ($1, $2, $3, $4, $5, $6, $7, false)`,
            [id, zone_id, req.user.id, status, notes || '-', date, time]
        );
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/logs/:id', authenticate, async (req, res) => {
    try {
        await pool.query('DELETE FROM logs WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Serve files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'), {
        setHeaders: (res) => {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
    });
});

app.use(express.static(__dirname));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 URL: http://localhost:${PORT}`);
});
