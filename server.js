const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Create folders for uploads if they don’t exist
['uploads', 'uploads/passports', 'uploads/documents'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});

// Configure Multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    if (file.fieldname === 'passportPhoto') {
      cb(null, 'uploads/passports');
    } else {
      cb(null, 'uploads/documents');
    }
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${Date.now()}${ext}`);
  }
});
const upload = multer({ storage });

const app = express();
const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(bodyParser.json());

const db = new sqlite3.Database('./users.db');

// Create tables
db.run(`CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firstName TEXT,
  lastName TEXT,
  dob TEXT,
  gender TEXT,
  address TEXT,
  grade TEXT,
  previousSchool TEXT,
  transferReason TEXT,
  parentName TEXT,
  parentRelationship TEXT,
  parentEmail TEXT,
  parentPhone TEXT,
  parentOccupation TEXT,
  passportPhoto TEXT,
  birthCert TEXT,
  reportCard TEXT,
  recommendation TEXT,
  status TEXT DEFAULT 'pending'
)`);

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  role TEXT
)`);

// Insert default admin
const insertAdmin = () => {
  const username = 'md';
  const password = '1234';
  const role = 'admin';

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) throw err;
    db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`, [username, hash, role]);
  });
};
insertAdmin();

// Routes
app.post('/login', (req, res) => {
  const { username, password, role } = req.body;
  db.get(`SELECT * FROM users WHERE username = ? AND role = ?`, [username, role], (err, user) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    if (!user) return res.status(401).json({ message: 'Invalid username or role' });

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (!isMatch) return res.status(401).json({ message: 'Incorrect password' });
      res.json({ message: 'Login successful', username: user.username });
    });
  });
});

app.post('/create-student-login', (req, res) => {
  const { surname, dob } = req.body;
  const username = surname.toLowerCase();
  const year = dob.split('/')[2];

  if (!year || year.length !== 4) {
    return res.status(400).json({ message: 'Invalid date of birth format.' });
  }

  const password = year;
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ message: 'Error hashing password' });

    db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`, [username, hash, 'student'], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'Failed to create login' });
      }
      res.json({ message: '✅ Student login created successfully!' });
    });
  });
});

app.post('/change-student-password', (req, res) => {
  const { username, newPassword } = req.body;

  bcrypt.hash(newPassword, 10, (err, hash) => {
    if (err) return res.status(500).json({ message: 'Error hashing password' });

    db.run(
      `UPDATE users SET password = ? WHERE username = ? AND role = 'student'`,
      [hash, username],
      function (err) {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: 'Failed to update password' });
        }
        if (this.changes === 0) {
          return res.status(404).json({ message: 'Student not found' });
        }
        res.json({ message: '✅ Password updated successfully!' });
      }
    );
  });
});

app.post('/create-teacher', (req, res) => {
  const { username, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, [username, hashed, 'teacher']);
  res.json({ message: 'Teacher created' });
});

// ✅ Register Student - with all fields and file upload
app.post('/register-student', upload.fields([
  { name: 'passportPhoto', maxCount: 1 },
  { name: 'birthCert', maxCount: 1 },
  { name: 'reportCard', maxCount: 1 },
  { name: 'recommendation', maxCount: 1 }
]), (req, res) => {
  const {
    firstName, lastName, dob, gender, address,
    grade, previousSchool, transferReason,
    parentName, parentRelationship, parentEmail,
    parentPhone, parentOccupation
  } = req.body;

  const passportPhoto = req.files['passportPhoto']?.[0]?.path || '';
  const birthCert = req.files['birthCert']?.[0]?.path || '';
  const reportCard = req.files['reportCard']?.[0]?.path || '';
  const recommendation = req.files['recommendation']?.[0]?.path || '';

  if (!firstName || !lastName || !dob || !gender || !address) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  db.run(`INSERT INTO students (
    firstName, lastName, dob, gender, address,
    grade, previousSchool, transferReason,
    parentName, parentRelationship, parentEmail,
    parentPhone, parentOccupation,
    passportPhoto, birthCert, reportCard, recommendation
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      firstName, lastName, dob, gender, address,
      grade, previousSchool, transferReason,
      parentName, parentRelationship, parentEmail,
      parentPhone, parentOccupation,
      passportPhoto, birthCert, reportCard, recommendation
    ],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'Failed to register student' });
      }
      res.json({ message: '✅ Student registered successfully!' });
    });
});

app.get('/students', (req, res) => {
  db.all(`SELECT * FROM users WHERE role = 'student'`, [], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Failed to load students' });
    }
    res.json(rows);
  });
});

app.get('/applications', (req, res) => {
  db.all(`SELECT * FROM students ORDER BY id DESC`, [], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Failed to fetch applications' });
    }
    res.json(rows);
  });
});

app.post('/applications/:id/status', (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ message: 'Invalid status' });
  }

  db.run(`UPDATE students SET status = ? WHERE id = ?`, [status, id], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Failed to update status' });
    }
    res.json({ message: `Student marked as ${status}` });
  });
});

app.get('/applications/approved', (req, res) => {
  db.all(`SELECT * FROM students WHERE status = 'approved'`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch approved applications' });
    res.json(rows);
  });
});

app.get('/applications/rejected', (req, res) => {
  db.all(`SELECT * FROM students WHERE status = 'rejected'`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch rejected applications' });
    res.json(rows);
  });
});

app.delete('/delete-student/:id', (req, res) => {
  const { id } = req.params;
  db.run(`DELETE FROM students WHERE id = ?`, [id], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Failed to delete student' });
    }
    res.json({ message: '✅ Student deleted successfully' });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
// Trigger redeploy
