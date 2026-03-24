const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@medicare.com';
const ADMIN_HASH = process.env.ADMIN_HASH;

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(h.split(' ')[1], JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (email !== ADMIN_EMAIL) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, ADMIN_HASH);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: 0, role: 'admin', name: 'Admin' }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: 0, role: 'admin', name: 'Admin' } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Doctor login
app.post('/api/doctor/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM doctors WHERE email=?', [email]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, rows[0].password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: rows[0].id, role: 'doctor', name: rows[0].name }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: rows[0].id, role: 'doctor', name: rows[0].name } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Patient login
app.post('/api/patient/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM patients WHERE email=?', [email]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, rows[0].password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: rows[0].id, role: 'patient', name: rows[0].name }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: rows[0].id, role: 'patient', name: rows[0].name } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Patient register
app.post('/api/patient/register', async (req, res) => {
  try {
    const { name, email, password, age, phone, blood } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const [r] = await pool.query('INSERT INTO patients (name,email,password,age,phone,blood_group) VALUES (?,?,?,?,?,?)', [name, email, hash, age||null, phone||null, blood||null]);
    const token = jwt.sign({ id: r.insertId, role: 'patient', name }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: r.insertId, role: 'patient', name } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Stats
app.get('/api/stats', auth, async (req, res) => {
  try {
    const [[{ doctors }]] = await pool.query('SELECT COUNT(*) as doctors FROM doctors');
    const [[{ patients }]] = await pool.query('SELECT COUNT(*) as patients FROM patients');
    const [[{ appointments }]] = await pool.query('SELECT COUNT(*) as appointments FROM appointments');
    const [[{ revenue }]] = await pool.query("SELECT COALESCE(SUM(amount),0) as revenue FROM billing WHERE status='Paid'");
    res.json({ doctors, patients, appointments, revenue });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Doctors CRUD
app.get('/api/doctors', auth, async (req, res) => {
  try { const [r] = await pool.query('SELECT id,name,speciality,phone,email,status FROM doctors'); res.json(r); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/doctors', auth, async (req, res) => {
  try {
    const { name, speciality, phone, email, password } = req.body;
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO doctors (name,speciality,phone,email,password) VALUES (?,?,?,?,?)', [name, speciality, phone, email, hash]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/doctors/:id', auth, async (req, res) => {
  try {
    const { name, speciality, phone, email, status } = req.body;
    await pool.query('UPDATE doctors SET name=?,speciality=?,phone=?,email=?,status=? WHERE id=?', [name, speciality, phone, email, status, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/doctors/:id', auth, async (req, res) => {
  try { await pool.query('DELETE FROM doctors WHERE id=?', [req.params.id]); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Patients
app.get('/api/patients', auth, async (req, res) => {
  try { const [r] = await pool.query('SELECT id,name,age,blood_group,phone,email,status FROM patients'); res.json(r); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Appointments
app.get('/api/appointments', auth, async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT a.*,p.name as patient_name,d.name as doctor_name FROM appointments a JOIN patients p ON a.patient_id=p.id JOIN doctors d ON a.doctor_id=d.id ORDER BY a.date DESC`);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/appointments/doctor', auth, async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT a.*,p.name as patient_name,p.age,p.blood_group FROM appointments a JOIN patients p ON a.patient_id=p.id WHERE a.doctor_id=? ORDER BY a.date DESC`, [req.user.id]);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/appointments/mine', auth, async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT a.*,d.name as doctor_name,d.speciality FROM appointments a JOIN doctors d ON a.doctor_id=d.id WHERE a.patient_id=? ORDER BY a.date DESC`, [req.user.id]);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/appointments', auth, async (req, res) => {
  try {
    const { doctor_id, date, time, reason } = req.body;
    await pool.query('INSERT INTO appointments (patient_id,doctor_id,date,time,reason) VALUES (?,?,?,?,?)', [req.user.id, doctor_id, date, time, reason]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/appointments/:id/status', auth, async (req, res) => {
  try { await pool.query('UPDATE appointments SET status=? WHERE id=?', [req.body.status, req.params.id]); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Prescriptions
app.get('/api/prescriptions/doctor', auth, async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT rx.*,p.name as patient_name FROM prescriptions rx JOIN patients p ON rx.patient_id=p.id WHERE rx.doctor_id=? ORDER BY rx.created_at DESC`, [req.user.id]);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/prescriptions/mine', auth, async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT rx.*,d.name as doctor_name FROM prescriptions rx JOIN doctors d ON rx.doctor_id=d.id WHERE rx.patient_id=? ORDER BY rx.created_at DESC`, [req.user.id]);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/prescriptions', auth, async (req, res) => {
  try {
    const { patient_id, diagnosis, medicines, notes } = req.body;
    await pool.query('INSERT INTO prescriptions (doctor_id,patient_id,diagnosis,medicines,notes) VALUES (?,?,?,?,?)', [req.user.id, patient_id, diagnosis, medicines, notes]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Billing
app.get('/api/billing', auth, async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT b.*,p.name as patient_name FROM billing b JOIN patients p ON b.patient_id=p.id ORDER BY b.date DESC`);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/billing/:id/pay', auth, async (req, res) => {
  try { await pool.query("UPDATE billing SET status='Paid' WHERE id=?", [req.params.id]); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: false,
  waitForConnections: true,
  connectionLimit: 10
});
