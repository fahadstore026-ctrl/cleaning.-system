// server.js - Cleaning System Server
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cleaning-system-secret-key-2026';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Prevent caching of static files
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

// Database connection
let pool = null;
if (process.env.DATABASE_URL) {
    pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { 
            rejectUnauthorized: false,
            requestCert: true
        },
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000
    });
    console.log('✅ Database connected successfully');
} else {
    console.error('❌ DATABASE_URL is not configured!');
}

// Initialize database tables
async function initDB() {
    if (!pool) {
        console.error('Cannot initialize database - no connection pool');
        return;
    }

    try {
        console.log('🔄 Initializing database...');
        
        // Drop old constraints if exist
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

        // Create logs table (without foreign key constraint on emp_id)
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
        console.log('✅ Logs table ready');

        // Create default admin user
        const result = await pool.query('SELECT COUNT(*) FROM users');
        const userCount = parseInt(result.rows[0].count);

        if (userCount === 0) {
            console.log('👑 Creating default admin user...');
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query(
                `INSERT INTO users (id, password, role, name_ar, name_en) 
                 VALUES ($1, $2, $3, $4, $5)`,
                ['admin', hashedPassword, 'مدير', 'المدير', 'Admin']
            );
            console.log('✅ Default admin created: admin / admin123');
        }

        console.log('✅ Database initialization complete');
    } catch (error) {
        console.error('❌ Database initialization error:', error.message);
        console.error(error.stack);
    }
}

// Run database initialization
initDB();

// Authentication middleware
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        return res.status(401).json({ error: 'No authorization header' });
    }
    
    const token = authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (error) {
        console.error('Token verification failed:', error.message);
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// ==================== API Routes ====================

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const { rows } = await pool.query(
            'SELECT * FROM users WHERE id = $1', 
            [username.toLowerCase().trim()]
        );
        
        if (!rows[0]) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        const isValidPassword = await bcrypt.compare(password, rows[0].password);
        
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign(
            { 
                id: rows[0].id, 
                role: rows[0].role,
                name_ar: rows[0].name_ar,
                name_en: rows[0].name_en
            },
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
        res.status(500).json({ error: error.message || 'Login failed' });
    }
});

// Get employees
app.get('/api/employees', authenticate, async (req, res) => {
    try {
        const { rows } = await pool.query(
            "SELECT id, role, name_ar, name_en, created_at FROM users WHERE id != 'admin' ORDER BY created_at DESC"
        );
        res.json(rows);
    } catch (error) {
        console.error('Get employees error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add employee
app.post('/api/employees', authenticate, async (req, res) => {
    try {
        const { id, name_ar, name_en, password, role } = req.body;
        
        if (!id || !name_ar || !password || !role) {
            return res.status(400).json({ error: 'All required fields must be filled' });
        }

        // Check if user already exists
        const existing = await pool.query('SELECT id FROM users WHERE id = $1', [id]);
        if (existing.rows.length > 0) {
            return res.status(409).json({ error: 'Employee ID already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            `INSERT INTO users (id, password, role, name_ar, name_en) 
             VALUES ($1, $2, $3, $4, $5)`,
            [id, hashedPassword, role, name_ar, name_en || name_ar]
        );
        
        res.json({ success: true, message: 'Employee added successfully' });
    } catch (error) {
        console.error('Add employee error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete employee (and their logs first)
app.delete('/api/employees/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        
        if (id === 'admin') {
            return res.status(400).json({ error: 'Cannot delete admin user' });
        }

        // First delete all logs for this employee
        await pool.query('DELETE FROM logs WHERE emp_id = $1', [id]);
        
        // Then delete the employee
        await pool.query('DELETE FROM users WHERE id = $1', [id]);
        
        res.json({ success: true, message: 'Employee deleted successfully' });
    } catch (error) {
        console.error('Delete employee error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get zones
app.get('/api/zones', authenticate, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM zones ORDER BY id');
        res.json(rows);
    } catch (error) {
        console.error('Get zones error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add zone
app.post('/api/zones', authenticate, async (req, res) => {
    try {
        const { id, name_ar, name_en } = req.body;
        
        if (!id || !name_ar) {
            return res.status(400).json({ error: 'ID and Arabic name are required' });
        }

        // Check if zone already exists
        const existing = await pool.query('SELECT id FROM zones WHERE id = $1', [id]);
        if (existing.rows.length > 0) {
            return res.status(409).json({ error: 'Zone ID already exists' });
        }

        await pool.query(
            'INSERT INTO zones (id, name_ar, name_en) VALUES ($1, $2, $3)',
            [id, name_ar, name_en || name_ar]
        );
        
        res.json({ success: true, message: 'Zone added successfully' });
    } catch (error) {
        console.error('Add zone error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete zone
app.delete('/api/zones/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('DELETE FROM zones WHERE id = $1', [id]);
        res.json({ success: true, message: 'Zone deleted successfully' });
    } catch (error) {
        console.error('Delete zone error:', error);
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
                   u.name_en as emp_name_en
            FROM logs l
            LEFT JOIN zones z ON l.zone_id = z.id
            LEFT JOIN users u ON l.emp_id = u.id
            ORDER BY l.ts DESC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Get logs error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add log
app.post('/api/logs', authenticate, async (req, res) => {
    try {
        const { zone_id, status, notes, date, time } = req.body;
        
        if (!zone_id || !status || !date || !time) {
            return res.status(400).json({ error: 'All required fields must be filled' });
        }

        const id = `LOG-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        
        await pool.query(
            `INSERT INTO logs (id, zone_id, emp_id, status, notes, date, time, edited) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, false)`,
            [id, zone_id, req.user.id, status, notes || '-', date, time]
        );
        
        res.json({ success: true, id, message: 'Log added successfully' });
    } catch (error) {
        console.error('Add log error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete log
app.delete('/api/logs/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('DELETE FROM logs WHERE id = $1', [id]);
        res.json({ success: true, message: 'Log deleted successfully' });
    } catch (error) {
        console.error('Delete log error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        database: pool ? 'connected' : 'disconnected'
    });
});

// Serve index.html with cache control
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'), {
        maxAge: 0,
        setHeaders: (res, path) => {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
    });
});

// Serve static files
app.use(express.static(__dirname, {
    maxAge: 0,
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
    }
}));

// Handle all other routes - serve index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'), {
        maxAge: 0,
        setHeaders: (res, path) => {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log('🚀 ====================================');
    console.log(`🚀 Server is running on port ${PORT}`);
    console.log(`🚀 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🚀 Time: ${new Date().toISOString()}`);
    console.log('🚀 ====================================');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('👋 SIGTERM received. Shutting down gracefully...');
    if (pool) {
        pool.end(() => {
            console.log('✅ Database pool closed');
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
});

process.on('SIGINT', () => {
    console.log('👋 SIGINT received. Shutting down gracefully...');
    if (pool) {
        pool.end(() => {
            console.log('✅ Database pool closed');
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
});
