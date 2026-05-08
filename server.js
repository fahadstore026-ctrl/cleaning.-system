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

// Middleware
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// Database connection
let pool = null;

if (process.env.DATABASE_URL) {
    pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });
    console.log('✅ Database connected successfully');
} else {
    console.error('❌ DATABASE_URL is not set!');
}

// Initialize database
async function initDB() {
    if (!pool) {
        console.error('Cannot initialize database - no connection');
        return;
    }

    try {
        // Drop old constraints if they exist
        try {
            await pool.query('ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check');
            await pool.query('ALTER TABLE users DROP CONSTRAINT IF EXISTS users_check');
            console.log('✅ Old constraints removed');
        } catch (e) {
            console.log('No old constraints to remove');
        }

        // Create users table
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
        console.log('✅ Users table ready');

        // Create zones table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS zones (
                id TEXT PRIMARY KEY,
                name_ar TEXT NOT NULL,
                name_en TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Zones table ready');

        // Create logs table
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
        console.log('✅ Logs table ready');

        // Create default admin if not exists
        const result = await pool.query('SELECT COUNT(*) FROM users');
        if (parseInt(result.rows[0].count) === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query(
                `INSERT INTO users (id, password, role, name_ar, name_en) 
                 VALUES ($1, $2, $3, $4, $5)`,
                ['admin', hashedPassword, 'مدير', 'المدير', 'Admin']
            );
            console.log('✅ Default admin created: admin / admin123');
        }

    } catch (error) {
        console.error('❌ Database initialization error:', error.message);
    }
}

// Run initialization
initDB();

// Authentication middleware
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Invalid token format' });
    }

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// ==================== API Routes ====================

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [username.toLowerCase()]);
        
        if (!rows[0]) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, rows[0].password);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: rows[0].id, role: rows[0].role }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );
        
        res.json({
            token,
            user: { 
                id: rows[0].id, 
                role: rows[0].role, 
                name_ar: rows[0].name_ar, 
                name_en: rows[0].name_en 
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get zones
app.get('/api/zones', authenticate, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM zones ORDER BY id');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add zone
app.post('/api/zones', authenticate, async (req, res) => {
    try {
        const { id, name_ar, name_en } = req.body;
        await pool.query(
            'INSERT INTO zones (id, name_ar, name_en) VALUES ($1, $2, $3)',
            [id, name_ar, name_en]
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete zone
app.delete('/api/zones/:id', authenticate, async (req, res) => {
    try {
        await pool.query('DELETE FROM zones WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get employees
app.get('/api/employees', authenticate, async (req, res) => {
    try {
        const { rows } = await pool.query(
            "SELECT id, role, name_ar, name_en, created_at FROM users WHERE id != 'admin'"
        );
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add employee
app.post('/api/employees', authenticate, async (req, res) => {
    try {
        const { id, name_ar, name_en, password, role } = req.body;
        
        if (!id || !name_ar || !name_en || !password || !role) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (id, password, role, name_ar, name_en) VALUES ($1, $2, $3, $4, $5)",
            [id, hashedPassword, role, name_ar, name_en]
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update employee
app.put('/api/employees/:id', authenticate, async (req, res) => {
    try {
        const { name_ar, name_en, role, password } = req.body;
        let query = 'UPDATE users SET name_ar = $1, name_en = $2, role = $3';
        let values = [name_ar, name_en, role];
        
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query += ', password = $4';
            values.push(hashedPassword);
        }
        
        query += ` WHERE id = $${values.length + 1}`;
        values.push(req.params.id);
        
        await pool.query(query, values);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete employee
app.delete('/api/employees/:id', authenticate, async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get logs
app.get('/api/logs', authenticate, async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT l.*, 
                   z.name_ar as zone_name_ar, 
                   z.name_en as zone_name_en, 
                   u.name_ar as emp_name_ar, 
                   u.name_en as emp_name_en, 
                   u.role as emp_role
            FROM logs l 
            JOIN zones z ON l.zone_id = z.id 
            JOIN users u ON l.emp_id = u.id 
            ORDER BY l.ts DESC
        `);
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add log
app.post('/api/logs', authenticate, async (req, res) => {
    try {
        const { zone_id, status, notes, date, time } = req.body;
        const id = `LOG-${Date.now()}`;
        
        await pool.query(
            `INSERT INTO logs (id, zone_id, emp_id, status, notes, date, time, edited) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, false)`,
            [id, zone_id, req.user.id, status, notes || '-', date, time]
        );
        res.json({ success: true, id });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete log
app.delete('/api/logs/:id', authenticate, async (req, res) => {
    try {
        await pool.query('DELETE FROM logs WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server is running' });
});

// Serve frontend - MUST be last route
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server is running on port ${PORT}`);
    console.log(`🌐 Local: http://localhost:${PORT}`);
    console.log(`🔗 Health: http://localhost:${PORT}/api/health`);
});
