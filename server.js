const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'medicare_secret_2026';

const pool = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME     || 'medicare_hms',
  waitForConnections: true,
  connectionLimit: 10,
});

function auth(roles = []) {
  return (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (roles.length && !roles.includes(decoded.role))
        return res.status(403).json({ error: 'Forbidden' });
      req.user = decoded;
      next();
    } catch {
      res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// Patient Register
app.post('/api/patient/register', async (req, res) => {
  const { name, email, password, age, blood, phone } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO patients (name, email, password, age, blood_group, phone) VALUES (?,?,?,?,?,?)',
      [name, email, hash, age || null, blood || null, phone || null]
    );
    const token = jwt.sign({ id: result.insertId, role: 'patient', name, email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: result.insertId, name, email, role: 'patient' } });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: e.message });
  }
});

// Patient Login
app.post('/api/patient/login', async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await pool.execute('SELECT * FROM patients WHERE email = ?', [email]);
  if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, rows[0].password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const user = rows[0];
  const token = jwt.sign({ id: user.id, role: 'patient', name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: 'patient' } });
});

// Doctor Login
app.post('/api/doctor/login', async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await pool.execute('SELECT * FROM doctors WHERE email = ?', [email]);
  if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, rows[0].password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const user = rows[0];
  const token = jwt.sign({ id: user.id, role: 'doctor', name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: 'doctor', spec: user.speciality } });
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (email !== (process.env.ADMIN_EMAIL || 'admin@medicare.com'))
    return res.status(401).json({ error: 'Invalid credentials' });
  const hash = process.env.ADMIN_HASH || '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi';
  const valid = await bcrypt.compare(password, hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: 0, role: 'admin', name: 'Admin', email }, JWT_SECRET, { expiresIn: '1d' });
  res.json({ token, user: { id: 0, name: 'Admin', email, role: 'admin' } });
});

// Doctors
app.get('/api/doctors', auth(['admin','patient']), async (req, res) => {
  const [rows] = await pool.execute('SELECT id,name,speciality,phone,email,status FROM doctors');
  res.json(rows);
});
app.post('/api/doctors', auth(['admin']), async (req, res) => {
  const { name, speciality, phone, email, password } = req.body;
  const hash = await bcrypt.hash(password || 'Doctor@123', 10);
  const [r] = await pool.execute(
    'INSERT INTO doctors (name, speciality, phone, email, password, status) VALUES (?,?,?,?,?,?)',
    [name, speciality, phone, email, hash, 'Active']
  );
  res.json({ id: r.insertId, name, speciality, phone, email, status: 'Active' });
});
app.put('/api/doctors/:id', auth(['admin']), async (req, res) => {
  const { name, speciality, phone, email, status } = req.body;
  await pool.execute(
    'UPDATE doctors SET name=?, speciality=?, phone=?, email=?, status=? WHERE id=?',
    [name, speciality, phone, email, status, req.params.id]
  );
  res.json({ success: true });
});
app.delete('/api/doctors/:id', auth(['admin']), async (req, res) => {
  await pool.execute('DELETE FROM doctors WHERE id=?', [req.params.id]);
  res.json({ success: true });
});

// Patients
app.get('/api/patients', auth(['admin','doctor']), async (req, res) => {
  const [rows] = await pool.execute('SELECT id,name,age,blood_group,phone,email,status FROM patients');
  res.json(rows);
});
app.get('/api/patients/me', auth(['patient']), async (req, res) => {
  const [rows] = await pool.execute('SELECT id,name,age,blood_group,phone,email,status FROM patients WHERE id=?', [req.user.id]);
  res.json(rows[0]);
});

// Appointments
app.get('/api/appointments', auth(['admin']), async (req, res) => {
  const [rows] = await pool.execute(`
    SELECT a.*, p.name AS patient_name, d.name AS doctor_name
    FROM appointments a
    JOIN patients p ON a.patient_id = p.id
    JOIN doctors  d ON a.doctor_id  = d.id
    ORDER BY a.date DESC, a.time ASC`);
  res.json(rows);
});
app.get('/api/appointments/mine', auth(['patient']), async (req, res) => {
  const [rows] = await pool.execute(`
    SELECT a.*, d.name AS doctor_name, d.speciality
    FROM appointments a JOIN doctors d ON a.doctor_id = d.id
    WHERE a.patient_id = ? ORDER BY a.date DESC`, [req.user.id]);
  res.json(rows);
});
app.get('/api/appointments/doctor', auth(['doctor']), async (req, res) => {
  const [rows] = await pool.execute(`
    SELECT a.*, p.name AS patient_name, p.age, p.blood_group
    FROM appointments a JOIN patients p ON a.patient_id = p.id
    WHERE a.doctor_id = ? ORDER BY a.date ASC, a.time ASC`, [req.user.id]);
  res.json(rows);
});
app.post('/api/appointments', auth(['patient']), async (req, res) => {
  const { doctor_id, date, time, reason } = req.body;
  const [r] = await pool.execute(
    'INSERT INTO appointments (patient_id, doctor_id, date, time, reason, status) VALUES (?,?,?,?,?,?)',
    [req.user.id, doctor_id, date, time, reason, 'Pending']
  );
  res.json({ id: r.insertId, status: 'Pending' });
});
app.put('/api/appointments/:id/status', auth(['admin','doctor']), async (req, res) => {
  await pool.execute('UPDATE appointments SET status=? WHERE id=?', [req.body.status, req.params.id]);
  res.json({ success: true });
});

// Prescriptions
app.get('/api/prescriptions/mine', auth(['patient']), async (req, res) => {
  const [rows] = await pool.execute(`
    SELECT pr.*, d.name AS doctor_name FROM prescriptions pr
    JOIN doctors d ON pr.doctor_id = d.id
    WHERE pr.patient_id = ? ORDER BY pr.created_at DESC`, [req.user.id]);
  res.json(rows);
});
app.get('/api/prescriptions/doctor', auth(['doctor']), async (req, res) => {
  const [rows] = await pool.execute(`
    SELECT pr.*, p.name AS patient_name FROM prescriptions pr
    JOIN patients p ON pr.patient_id = p.id
    WHERE pr.doctor_id = ? ORDER BY pr.created_at DESC`, [req.user.id]);
  res.json(rows);
});
app.post('/api/prescriptions', auth(['doctor']), async (req, res) => {
  const { patient_id, diagnosis, medicines, notes } = req.body;
  const [r] = await pool.execute(
    'INSERT INTO prescriptions (doctor_id, patient_id, diagnosis, medicines, notes) VALUES (?,?,?,?,?)',
    [req.user.id, patient_id, diagnosis, medicines, notes]
  );
  res.json({ id: r.insertId });
});

// Billing
app.get('/api/billing', auth(['admin']), async (req, res) => {
  const [rows] = await pool.execute(`
    SELECT b.*, p.name AS patient_name FROM billing b
    JOIN patients p ON b.patient_id = p.id ORDER BY b.date DESC`);
  res.json(rows);
});
app.post('/api/billing', auth(['admin']), async (req, res) => {
  const { patient_id, amount, type, date } = req.body;
  const [r] = await pool.execute(
    'INSERT INTO billing (patient_id, amount, type, date, status) VALUES (?,?,?,?,?)',
    [patient_id, amount, type, date, 'Pending']
  );
  res.json({ id: r.insertId });
});
app.put('/api/billing/:id/pay', auth(['admin']), async (req, res) => {
  await pool.execute('UPDATE billing SET status="Paid" WHERE id=?', [req.params.id]);
  res.json({ success: true });
});

// Stats
app.get('/api/stats', auth(['admin']), async (req, res) => {
  const [[{ doctors }]] = await pool.execute('SELECT COUNT(*) AS doctors FROM doctors');
  const [[{ patients }]] = await pool.execute('SELECT COUNT(*) AS patients FROM patients');
  const [[{ appointments }]] = await pool.execute('SELECT COUNT(*) AS appointments FROM appointments');
  const [[{ revenue }]] = await pool.execute('SELECT COALESCE(SUM(amount),0) AS revenue FROM billing WHERE status="Paid"');
  const [[{ pending_billing }]] = await pool.execute('SELECT COALESCE(SUM(amount),0) AS pending_billing FROM billing WHERE status="Pending"');
  res.json({ doctors, patients, appointments, revenue, pending_billing });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MediCare HMS running on http://localhost:${PORT}`));
