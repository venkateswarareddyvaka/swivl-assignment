const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'swivl',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

pool.getConnection((err, connection) => {
  if (err) {
    console.error('Error connecting to MySQL database: ' + err.stack);
    return;
  }
  
  console.log('Connected to MySQL database as id ' + connection.threadId);
  connection.release();
});

// Generate JWT Secret Key
const JWT_SECRET = crypto.randomBytes(32).toString('hex');

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(401).send('Access Denied. Token is not provided.');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    return res.status(403).send('Invalid Token.');
  }
}

// Input validation middleware
function validateInputs(req, res, next) {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).send('Missing required fields.');
  }
  next();
}

// Error handling middleware
function errorHandler(err, req, res, next) {
  console.error('Error:', err);
  res.status(500).send('Internal Server Error');
}

// Routes for user operations
const userRoutes = express.Router();

userRoutes.post('/register', validateInputs, async (req, res, next) => {
  const { username, email, password } = req.body;
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, password]);
    connection.release();
    const userId = result.insertId;
    const token = jwt.sign({ userId }, JWT_SECRET);
    res.status(201).json({ userId, token });
  } catch (error) {
    next(error);
  }
});

userRoutes.post('/login', validateInputs, async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT * FROM users WHERE email = ? AND password = ?', [email, password]);
    connection.release();
    if (rows.length === 0) {
      return res.status(401).send('Invalid credentials');
    }
    const userId = rows[0].id;
    const token = jwt.sign({ userId }, JWT_SECRET);
    res.status(200).json({ userId, token });
  } catch (error) {
    next(error);
  }
});

userRoutes.put('/:userId', verifyToken, validateInputs, async (req, res, next) => {
  const { userId } = req.params;
  const { newUsername, newEmail } = req.body;
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.query('UPDATE users SET username = ?, email = ? WHERE id = ?', [newUsername, newEmail, userId]);
    connection.release();
    if (result.affectedRows === 0) {
      return res.status(404).send('User not found');
    }
    res.status(200).send('User updated successfully');
  } catch (error) {
    next(error);
  }
});

userRoutes.delete('/:userId', verifyToken, async (req, res, next) => {
  const { userId } = req.params;
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.query('DELETE FROM users WHERE id = ?', [userId]);
    connection.release();
    if (result.affectedRows === 0) {
      return res.status(404).send('User not found');
    }
    res.status(200).send('User deleted successfully');
  } catch (error) {
    next(error);
  }
});


const diaryEntryRoutes = express.Router();

diaryEntryRoutes.post('/', verifyToken, validateInputs, async (req, res, next) => {
  const { userId, location, date, entry } = req.body;
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.query('INSERT INTO diary_entries (user_id, location, date, entry) VALUES (?, ?, ?, ?)', [userId, location, date, entry]);
    connection.release();
    const entryId = result.insertId;
    res.status(201).json({ entryId });
  } catch (error) {
    next(error);
  }
});

diaryEntryRoutes.get('/:entryId', verifyToken, async (req, res, next) => {
  const { entryId } = req.params;
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT * FROM diary_entries WHERE id = ?', [entryId]);
    connection.release();
    if (rows.length === 0) {
      return res.status(404).send('Diary entry not found');
    }
    const entry = rows[0];
    res.status(200).json(entry);
  } catch (error) {
    next(error);
  }
});

diaryEntryRoutes.put('/:entryId', verifyToken, validateInputs, async (req, res, next) => {
  const { entryId } = req.params;
  const { newLocation, newDate, newEntry } = req.body;
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.query('UPDATE diary_entries SET location = ?, date = ?, entry = ? WHERE id = ?', [newLocation, newDate, newEntry, entryId]);
    connection.release();
    if (result.affectedRows === 0) {
      return res.status(404).send('Diary entry not found');
    }
    res.status(200).send('Diary entry updated successfully');
  } catch (error) {
    next(error);
  }
});

diaryEntryRoutes.delete('/:entryId', verifyToken, async (req, res, next) => {
  const { entryId } = req.params;
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.query('DELETE FROM diary_entries WHERE id = ?', [entryId]);
    connection.release();
    if (result.affectedRows === 0) {
      return res.status(404).send('Diary entry not found');
    }
    res.status(200).send('Diary entry deleted successfully');
  } catch (error) {
    next(error);
  }
});


app.use(express.json());

app.use('/users', userRoutes);
app.use('/diary-entries', diaryEntryRoutes);

app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`JWT Secret Key: ${JWT_SECRET}`);
});
