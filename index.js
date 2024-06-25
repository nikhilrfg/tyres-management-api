const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

require('dotenv').config();

const app = express();
const port = process.env.PORT;

const corsOptions = {
  origin: '*',
  credentials: true,
  'access-control-allow-credentials': true,
  optionSuccessStatus: 200,
};

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

app.use(cors(corsOptions));
app.use(bodyParser.json());

app.use(async (req, res, next) => {
  try {
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;
    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);
    await next();
    req.db.release();
  } catch (err) {
    console.log(err);
    if (req.db) req.db.release();
    throw err;
  }
});

// Register endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await req.db.query(
      `INSERT INTO users (username, password) VALUES (:username, :password)`,
      { username, password: hashedPassword }
    );

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const [[user]] = await req.db.query(
      `SELECT * FROM users WHERE username = :username`,
      { username }
    );

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    // if (isMatch) {
    //   const payload = {
    //     userId: user.id,
    //     username: user.username,
    //     userIsAdmin: user.admin_flag
    //   }

    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_KEY, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// JWT verification middleware
app.use((req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Authorization header missing' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// CRUD Endpoints for Tyres
// Create a tyre
app.post('/tyres', async (req, res) => {
  try {
    const { brand, model, size } = req.body;
    const [result] = await req.db.query(
      `INSERT INTO tyres (brand, model, size, user_id) VALUES (:brand, :model, :size, :user_id)`,
      { brand, model, size, user_id: req.user.id }
    );

    res.status(201).json({ id: result.insertId, brand, model, size });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Failed to create tyre' });
  }
});

// Read all tyres
app.get('/tyres', async (req, res) => {
  try {
    const [tyres] = await req.db.query(
      `SELECT * FROM tyres WHERE user_id = :user_id`,
      { user_id: req.user.id }
    );

    res.json(tyres);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Failed to fetch tyres' });
  }
});

// Update a tyre
app.put('/tyres/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { brand, model, size } = req.body;
    await req.db.query(
      `UPDATE tyres SET brand = :brand, model = :model, size = :size WHERE id = :id AND user_id = :user_id`,
      { brand, model, size, id, user_id: req.user.id }
    );

    res.json({ id, brand, model, size });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Failed to update tyre' });
  }
});

// Delete a tyre
app.delete('/tyres/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await req.db.query(
      `DELETE FROM tyres WHERE id = :id AND user_id = :user_id`,
      { id, user_id: req.user.id }
    );

    res.json({ message: 'Tyre deleted successfully' });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Failed to delete tyre' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
