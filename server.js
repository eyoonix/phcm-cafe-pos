const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const SECRET = 'change_this_secret_in_prod';
const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use('/', express.static('public'));
app.use('/photos', express.static('photos'));

/* Database */
const db = new sqlite3.Database('./pos.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)`);

    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        name TEXT, 
        price REAL, 
        cost_price REAL DEFAULT 0, 
        stock INTEGER, 
        photo_path TEXT
    )`);

    // Restock Logs
    db.run(`CREATE TABLE IF NOT EXISTS restock_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        qty_added INTEGER,
        cost_at_time REAL,
        created_at DATETIME DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )`);

    // Sales Logs
    db.run(`CREATE TABLE IF NOT EXISTS sales (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        product_id INTEGER, 
        qty INTEGER, 
        total REAL, 
        created_at DATETIME DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )`);

    db.get(`SELECT COUNT(*) as c FROM users`, (err, row) => {
        if (!err && row.c === 0) {
            const hashed = bcrypt.hashSync('phcm123', 8);
            db.run(`INSERT INTO users (username, password) VALUES (?,?)`, ['phcm', hashed]);
        }
    });

    db.get(`SELECT COUNT(*) as c FROM products`, (err, row) => {
        if (!err && row.c === 0) {
            const stmt = db.prepare(`INSERT INTO products (name, price, stock, photo_path) VALUES (?,?,?,?)`);
            stmt.run('PORKCHOP', 85, 10, '/photos/porkchop.jpg');
            stmt.run('FRIED CHICKEN', 80, 10, '/photos/fried-siken.png');
            stmt.run('ZEST-0', 15, 10, '/photos/zesto.jpg');
            stmt.run('COKE', 20, 10, '/photos/coke.jpg');
            stmt.run('C2', 25, 10, '/photos/c2.jpg');
            stmt.finalize();
        }
    });
});

const auth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access denied." });
    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token." });
        req.user = user;
        next();
    });
};

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '8h' });
        res.json({ token, username: user.username });
    });
});

// =================================================================
// PRODUCTS (CRUD)
// =================================================================
app.get('/api/products', auth, (req, res) => {
    db.all(`SELECT * FROM products`, (err, rows) => res.json(rows));
});

app.post('/api/products', auth, (req, res) => {
    const { name, price, cost_price, stock, photo_path } = req.body; 
    db.run(`INSERT INTO products (name, price, cost_price, stock, photo_path) VALUES (?,?,?,?,?)`, 
        [name, price, cost_price || 0, stock, photo_path], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID });
    });
});

// FIXED: This route now protects your images from changing/disappearing
app.put('/api/products/:id', auth, (req, res) => {
    const { id } = req.params;
    const { name, price, cost_price, stock, photo_path } = req.body; 

    // 1. First, get the current product to check the existing image
    db.get(`SELECT photo_path, stock FROM products WHERE id = ?`, [id], (err, row) => {
        if (err || !row) return res.status(500).json({ error: "Product not found" });

        // 2. If photo_path in request is empty/null, use the one already in the DB
        const finalPhoto = (photo_path && photo_path.trim() !== "") ? photo_path : row.photo_path;
        
        const oldStock = row.stock;
        const addedQty = stock - oldStock;

        // 3. Update with the protected photo path
        db.run(`UPDATE products SET name=?, price=?, cost_price=?, stock=?, photo_path=? WHERE id=?`, 
            [name, price, cost_price, stock, finalPhoto, id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            if (addedQty > 0) {
                db.run(`INSERT INTO restock_logs (product_id, qty_added, cost_at_time) VALUES (?,?,?)`,
                    [id, addedQty, cost_price]);
            }
            res.json({ success: true });
        });
    });
});

app.delete('/api/products/:id', auth, (req, res) => {
    db.run(`DELETE FROM products WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ changes: this.changes });
    });
});

// =================================================================
// SALES & STATS
// =================================================================
app.post('/api/sales', auth, (req, res) => {
    const { items } = req.body;
    if (!items || !Array.isArray(items)) return res.status(400).json({ error: 'No items' });

    db.serialize(() => {
        items.forEach(it => {
            db.get(`SELECT price FROM products WHERE id = ?`, [it.product_id], (err, p) => {
                if (!err && p) {
                    const lineTotal = p.price * it.qty;
                    db.run(`INSERT INTO sales (product_id, qty, total) VALUES (?,?,?)`, [it.product_id, it.qty, lineTotal]);
                    db.run(`UPDATE products SET stock = stock - ? WHERE id = ?`, [it.qty, it.product_id]);
                }
            });
        });
        db.run('SELECT 1', () => res.json({ success: true }));
    });
});

app.get('/api/sales/history', auth, (req, res) => {
    const query = `SELECT s.id, p.name as product_name, s.qty, s.total, s.created_at FROM sales s JOIN products p ON s.product_id = p.id ORDER BY s.created_at DESC`;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/stats', auth, (req, res) => {
    const summaryQuery = `SELECT COALESCE(SUM(s.total), 0) as revenue, COUNT(s.id) as total_sales, COALESCE(SUM((p.price - p.cost_price) * s.qty), 0) as profit FROM sales s JOIN products p ON s.product_id = p.id`;
    const topItemsQuery = `SELECT p.name, SUM(s.qty) as sold FROM sales s JOIN products p ON s.product_id = p.id GROUP BY s.product_id ORDER BY sold DESC LIMIT 5`;

    db.get(summaryQuery, [], (err, summary) => {
        if (err) return res.status(500).json({ error: err.message });
        db.all(topItemsQuery, [], (err, topItems) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ revenue: summary.revenue, total_sales: summary.total_sales, profit: summary.profit, top_items: topItems || [] });
        });
    });
});

app.get('/api/inventory/restock-history', auth, (req, res) => {
    const query = `SELECT r.id, p.name as product_name, r.qty_added, r.cost_at_time, r.created_at FROM restock_logs r JOIN products p ON r.product_id = p.id ORDER BY r.created_at DESC`;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

const PORT = 5500;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));