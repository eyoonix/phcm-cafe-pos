const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const SECRET = 'change_this_secret_in_prod';
const app = express();
app.use(bodyParser.json());
app.use(cors());

app.use('/', express.static('public'));
app.use('/photos', express.static('photos'));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

/* Database */
const db = new sqlite3.Database('./pos.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    cost_price REAL DEFAULT 0,
    stock INTEGER,
    photo_path TEXT
  )`);

  // ✅ NEW: Transactions table (1 row = 1 order)
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grand_total REAL DEFAULT 0,
    cash REAL DEFAULT 0,
    change REAL DEFAULT 0,
    created_at DATETIME DEFAULT (datetime('now','localtime'))
  )`);

  // Sales lines (each row = item in a transaction)
  db.run(`CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id INTEGER,
    product_id INTEGER,
    qty INTEGER,
    total REAL,
    created_at DATETIME DEFAULT (datetime('now','localtime')),
    FOREIGN KEY(product_id) REFERENCES products(id),
    FOREIGN KEY(transaction_id) REFERENCES transactions(id)
  )`);

  // In case you had an old sales table without transaction_id, try to add it (ignore error if already exists)
  db.run(`ALTER TABLE sales ADD COLUMN transaction_id INTEGER`, () => {});

  // Restock Logs
  db.run(`CREATE TABLE IF NOT EXISTS restock_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER,
    qty_added INTEGER,
    cost_at_time REAL,
    created_at DATETIME DEFAULT (datetime('now','localtime')),
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
  db.run(
    `INSERT INTO products (name, price, cost_price, stock, photo_path) VALUES (?,?,?,?,?)`,
    [name, price, cost_price || 0, stock, photo_path],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

app.put('/api/products/:id', auth, (req, res) => {
  const { id } = req.params;
  const { name, price, cost_price, stock, photo_path } = req.body;

  db.get(`SELECT photo_path, stock FROM products WHERE id = ?`, [id], (err, row) => {
    if (err || !row) return res.status(500).json({ error: "Product not found" });

    const finalPhoto = (photo_path && photo_path.trim() !== "") ? photo_path : row.photo_path;

    const oldStock = row.stock;
    const addedQty = stock - oldStock;

    db.run(
      `UPDATE products SET name=?, price=?, cost_price=?, stock=?, photo_path=? WHERE id=?`,
      [name, price, cost_price, stock, finalPhoto, id],
      function (err2) {
        if (err2) return res.status(500).json({ error: err2.message });

        if (addedQty > 0) {
          db.run(
            `INSERT INTO restock_logs (product_id, qty_added, cost_at_time) VALUES (?,?,?)`,
            [id, addedQty, cost_price]
          );
        }
        res.json({ success: true });
      }
    );
  });
});

app.delete('/api/products/:id', auth, (req, res) => {
  db.run(`DELETE FROM products WHERE id = ?`, [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ changes: this.changes });
  });
});

// =================================================================
// SALES / TRANSACTIONS
// =================================================================

// ✅ POST SALE: creates 1 transaction id, then inserts line items into sales
app.post('/api/sales', auth, (req, res) => {
  const { items, payment } = req.body;

  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'No items in cart' });
  }

  db.serialize(() => {
    db.run("BEGIN TRANSACTION");

    // 1) compute total first (we'll also validate stock)
    let grandTotal = 0;

    const validateAndCompute = (idx) => {
      if (idx >= items.length) return createTransactionRow();

      const it = items[idx];
      if (!it || !it.product_id || !it.qty) {
        db.run("ROLLBACK");
        return res.status(400).json({ error: "Invalid cart item." });
      }

      db.get(`SELECT stock, price, name FROM products WHERE id = ?`, [it.product_id], (err, p) => {
        if (err || !p) {
          db.run("ROLLBACK");
          return res.status(400).json({ error: "Invalid product in cart." });
        }
        if (p.stock < it.qty) {
          db.run("ROLLBACK");
          return res.status(400).json({ error: `Insufficient stock for ${p.name}` });
        }

        grandTotal += (p.price * it.qty);
        validateAndCompute(idx + 1);
      });
    };

    const createTransactionRow = () => {
      const cash = Number(payment || 0);
      const change = cash - grandTotal;

      if (cash < grandTotal) {
        db.run("ROLLBACK");
        return res.status(400).json({ error: "Cash is not enough." });
      }

      db.run(
        `INSERT INTO transactions (grand_total, cash, change) VALUES (?,?,?)`,
        [grandTotal, cash, change],
        function (err) {
          if (err) {
            db.run("ROLLBACK");
            return res.status(500).json({ error: err.message });
          }

          const transactionId = this.lastID;

          // 2) insert sales lines + deduct stock
          insertLines(transactionId, 0);
        }
      );
    };

    const insertLines = (transactionId, idx) => {
      if (idx >= items.length) {
        // get created_at of this transaction and commit
        db.get(`SELECT created_at FROM transactions WHERE id = ?`, [transactionId], (err, row) => {
          if (err || !row) {
            db.run("ROLLBACK");
            return res.status(500).json({ error: "Transaction created but timestamp missing." });
          }

          db.run("COMMIT", (err2) => {
            if (err2) {
              db.run("ROLLBACK");
              return res.status(500).json({ error: "Commit failed." });
            }

            return res.json({
              success: true,
              transaction_id: transactionId,
              created_at: row.created_at,
              grand_total: grandTotal
            });
          });
        });
        return;
      }

      const it = items[idx];

      db.get(`SELECT price FROM products WHERE id = ?`, [it.product_id], (err, p) => {
        if (err || !p) {
          db.run("ROLLBACK");
          return res.status(400).json({ error: "Invalid product while inserting sale." });
        }

        const lineTotal = p.price * it.qty;

        db.run(
          `INSERT INTO sales (transaction_id, product_id, qty, total, created_at)
           VALUES (?,?,?,?, (datetime('now','localtime')))`,
          [transactionId, it.product_id, it.qty, lineTotal],
          (err2) => {
            if (err2) {
              db.run("ROLLBACK");
              return res.status(500).json({ error: err2.message });
            }

            db.run(`UPDATE products SET stock = stock - ? WHERE id = ?`, [it.qty, it.product_id], (err3) => {
              if (err3) {
                db.run("ROLLBACK");
                return res.status(500).json({ error: err3.message });
              }
              insertLines(transactionId, idx + 1);
            });
          }
        );
      });
    };

    validateAndCompute(0);
  });
});

// ✅ Transaction list for history page (ONE row = ONE transaction)
app.get('/api/sales/transactions', auth, (req, res) => {
  const query = `
    SELECT
      t.id as transaction_id,
      t.created_at,
      COUNT(s.id) as item_count,
      ROUND(t.grand_total, 2) as grand_total,
      GROUP_CONCAT(p.name || ' (x' || s.qty || ')') as items_summary
    FROM transactions t
    LEFT JOIN sales s ON s.transaction_id = t.id
    LEFT JOIN products p ON p.id = s.product_id
    GROUP BY t.id
    ORDER BY t.id DESC
  `;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

// ✅ Receipt by transaction_id
app.get('/api/sales/receipt', auth, (req, res) => {
  const { transaction_id } = req.query;
  if (!transaction_id) return res.status(400).json({ error: "transaction_id is required" });

  const itemsQuery = `
    SELECT
      p.name as name,
      s.qty as qty,
      ROUND((s.total * 1.0) / s.qty, 2) as unit_price,
      ROUND(s.total, 2) as line_total
    FROM sales s
    JOIN products p ON p.id = s.product_id
    WHERE s.transaction_id = ?
    ORDER BY s.id ASC
  `;

  db.get(`SELECT id, created_at, grand_total, cash, change FROM transactions WHERE id = ?`, [transaction_id], (err, tx) => {
    if (err || !tx) return res.status(404).json({ error: "Transaction not found" });

    db.all(itemsQuery, [transaction_id], (err2, items) => {
      if (err2) return res.status(500).json({ error: err2.message });

      res.json({
        transaction_id: tx.id,
        created_at: tx.created_at,
        items: items || [],
        grand_total: tx.grand_total,
        cash: tx.cash,
        change: tx.change
      });
    });
  });
});

// =================================================================
// STATS / ALERTS / RESTOCK
// =================================================================
app.get('/api/stats', auth, (req, res) => {
  const summaryQuery = `
    SELECT
      COALESCE(SUM(s.total), 0) as revenue,
      COUNT(s.id) as total_sales,
      COALESCE(SUM((p.price - IFNULL(p.cost_price, 0)) * s.qty), 0) as profit
    FROM sales s
    JOIN products p ON s.product_id = p.id
  `;

  const topItemsQuery = `
    SELECT p.name, SUM(s.qty) as sold
    FROM sales s
    JOIN products p ON s.product_id = p.id
    GROUP BY s.product_id
    ORDER BY sold DESC
    LIMIT 5
  `;

  db.get(summaryQuery, [], (err, summary) => {
    if (err) return res.status(500).json({ error: err.message });
    db.all(topItemsQuery, [], (err2, topItems) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({
        revenue: summary.revenue,
        total_sales: summary.total_sales,
        profit: summary.profit,
        top_items: topItems || []
      });
    });
  });
});

app.get('/api/alerts/low-stock', auth, (req, res) => {
  db.all(`SELECT name, stock FROM products WHERE stock <= 5`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/inventory/restock-history', auth, (req, res) => {
  const query = `
    SELECT r.id, p.name as product_name, r.qty_added, r.cost_at_time, r.created_at
    FROM restock_logs r
    JOIN products p ON r.product_id = p.id
    ORDER BY r.created_at DESC
  `;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

const PORT = process.env.PORT || 5500;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});