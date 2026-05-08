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

// Middleware - MUST be first
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Database
let pool = null;
if (process.env.DATABASE_URL) {
    pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });
    console.log('✅ Database connected');
}

// Initialize DB
async function initDB() {
    if (!pool) return;
    try {
        // Drop constraints
        await pool.query('ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check').catch(() => {});
        
        // Users table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                name_ar TEXT NOT NULL,
                name_en TEXT NOT NULL,
                permissions JSONB DEFAULT '{"can_add_logs": false, "can_view_logs": false, "can_manage_employees": false, "can_manage_zones": false}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Zones & Logs tables
        await pool.query(`CREATE TABLE IF NOT EXISTS zones (id TEXT PRIMARY KEY, name_ar TEXT NOT NULL, name_en TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS logs (id TEXT PRIMARY KEY, zone_id TEXT REFERENCES zones(id) ON DELETE CASCADE, emp_id TEXT REFERENCES users(id) ON DELETE CASCADE, status TEXT NOT NULL, notes TEXT, date TEXT NOT NULL, time TEXT NOT NULL, ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP, edited BOOLEAN DEFAULT FALSE)`);

        // Default admin
        const res = await pool.query('SELECT COUNT(*) FROM users');
        if (parseInt(res.rows[0].count) === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await pool.query(
                `INSERT INTO users (id, password, role, name_ar, name_en, permissions) VALUES ($1, $2, $3, $4, $5, $6)`,
                ['admin', hash, 'مدير', 'المدير', 'Admin', '{"can_add_logs": true, "can_view_logs": true, "can_manage_employees": true, "can_manage_zones": true}']
            );
            console.log('👑 Admin created');
        }
    } catch (e) { console.error('DB Error:', e); }
}
initDB();

// Auth Middleware
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch { res.status(403).json({ error: 'Invalid token' }); }
};

// Permission check middleware
const checkPermission = (permission) => {
    return (req, res, next) => {
        if (!req.user.permissions || !req.user.permissions[permission]) {
            return res.status(403).json({ error: 'No permission' });
        }
        next();
    };
};

// ==================== API Routes ====================

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [username.toLowerCase()]);
        if (!rows[0]) return res.status(401).json({ error: 'Invalid' });
        
        const valid = await bcrypt.compare(password, rows[0].password);
        if (!valid) return res.status(401).json({ error: 'Invalid' });

        const token = jwt.sign(
            { id: rows[0].id, role: rows[0].role, permissions: rows[0].permissions }, 
            JWT_SECRET, { expiresIn: '24h' }
        );
        
        res.json({
            token,
            user: { 
                id: rows[0].id, 
                role: rows[0].role, 
                name_ar: rows[0].name_ar, 
                name_en: rows[0].name_en,
                permissions: rows[0].permissions
            }
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get employees (Admin only)
app.get('/api/employees', authenticate, checkPermission('can_manage_employees'), async (req, res) => {
    try {
        const { rows } = await pool.query("SELECT id, role, name_ar, name_en, permissions FROM users WHERE id != 'admin'");
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Add employee (Admin only)
app.post('/api/employees', authenticate, checkPermission('can_manage_employees'), async (req, res) => {
    try {
        const { id, name_ar, name_en, password, role, permissions } = req.body;
        const hash = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (id, password, role, name_ar, name_en, permissions) VALUES ($1, $2, $3, $4, $5, $6)",
            [id, hash, role, name_ar, name_en, JSON.stringify(permissions || {})]
        );
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update employee (Admin only)
app.put('/api/employees/:id', authenticate, checkPermission('can_manage_employees'), async (req, res) => {
    try {
        const { name_ar, name_en, role, password, permissions } = req.body;
        let sql = "UPDATE users SET name_ar=$1, name_en=$2, role=$3";
        let params = [name_ar, name_en, role];
        
        if (password) {
            const hash = await bcrypt.hash(password, 10);
            sql += ", password=$4";
            params.push(hash);
        }
        if (permissions) {
            sql += ", permissions=$" + (params.length + 1);
            params.push(JSON.stringify(permissions));
        }
        
        sql += " WHERE id=$" + (params.length + 1);
        params.push(req.params.id);
        
        await pool.query(sql, params);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete employee (Admin only)
app.delete('/api/employees/:id', authenticate, checkPermission('can_manage_employees'), async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Zones (Admin only)
app.get('/api/zones', authenticate, checkPermission('can_manage_zones'), async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM zones ORDER BY id');
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/zones', authenticate, checkPermission('can_manage_zones'), async (req, res) => {
    try {
        const { id, name_ar, name_en } = req.body;
        await pool.query('INSERT INTO zones (id, name_ar, name_en) VALUES ($1, $2, $3)', [id, name_ar, name_en]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/zones/:id', authenticate, checkPermission('can_manage_zones'), async (req, res) => {
    try {
        await pool.query('DELETE FROM zones WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Logs - All authenticated users can view their own or all (based on permission)
app.get('/api/logs', authenticate, async (req, res) => {
    try {
        let query = `
            SELECT l.*, z.name_ar as zone_name_ar, z.name_en as zone_name_en, 
                   u.name_ar as emp_name_ar, u.name_en as emp_name_en, u.role as emp_role
            FROM logs l 
            JOIN zones z ON l.zone_id = z.id 
            JOIN users u ON l.emp_id = u.id 
        `;
        
        // If user can't view all logs, show only their own
        if (!req.user.permissions.can_view_logs) {
            query += ` WHERE l.emp_id = '${req.user.id}'`;
        }
        
        query += ' ORDER BY l.ts DESC';
        
        const { rows } = await pool.query(query);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Add log (Cleaners & authorized users)
app.post('/api/logs', authenticate, checkPermission('can_add_logs'), async (req, res) => {
    try {
        const { zone_id, status, notes, date, time } = req.body;
        const id = `LOG-${Date.now()}`;
        
        await pool.query(
            `INSERT INTO logs (id, zone_id, emp_id, status, notes, date, time, edited) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, false)`,
            [id, zone_id, req.user.id, status, notes || '-', date, time]
        );
        res.json({ success: true, id });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/logs/:id', authenticate, async (req, res) => {
    try {
        await pool.query('DELETE FROM logs WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Serve frontend - MUST BE LAST
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
});

// Start
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server on port ${PORT}`);
});
