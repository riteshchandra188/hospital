const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());

const publicPath = path.join(__dirname, 'public');
if (fs.existsSync(publicPath)) {
  app.use(express.static(publicPath));
}

const pool = mysql.createPool({
  host: process.env.MYSQLHOST || process.env.DB_HOST,
  port: parseInt(process.env.MYSQLPORT || process.env.DB_PORT) || 3306,
  user: process.env.MYSQLUSER || process.env.DB_USER,
  password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD,
  database: process.env.MYSQLDATABASE || process.env.DB_NAME,
  ssl: false,
  waitForConnections: true,
  connectionLimit: 10
});

const JWT_SECRET = process.env.JWT_SECRET || 'medicare_secret_2026';

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(h.split(' ')[1], JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM admins WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const admin = rows[0];
    if (admin.status !== 'Active') return res.status(403).json({ error: 'Admin account is inactive' });
    const ok = await bcrypt.compare(password, admin.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(
      { id: admin.id, role: 'admin', name: admin.name },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token, user: { id: admin.id, role: 'admin', name: admin.name, email: admin.email } });
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
    const [r] = await pool.query(
      'INSERT INTO patients (name,email,password,age,phone,blood_group) VALUES (?,?,?,?,?,?)',
      [name, email, hash, age||null, phone||null, blood||null]
    );
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

// Doctors
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
// ─── Receptionists ───────────────────────────────────────────

// Receptionist login
app.post('/api/receptionist/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM receptionists WHERE email = ?', [email]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const rec = rows[0];
    if (rec.status !== 'Active') return res.status(403).json({ error: 'Account is inactive' });
    const ok = await bcrypt.compare(password, rec.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: rec.id, role: 'receptionist', name: rec.name }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: rec.id, role: 'receptionist', name: rec.name, email: rec.email } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get all receptionists (Admin)
app.get('/api/receptionists', auth, async (req, res) => {
  try {
    const [r] = await pool.query('SELECT id, name, email, phone, status, created_at FROM receptionists');
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Add receptionist (Admin)
app.post('/api/receptionists', auth, async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO receptionists (name, email, password, phone) VALUES (?,?,?,?)',
      [name, email, hash, phone||null]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update receptionist (Admin)
app.put('/api/receptionists/:id', auth, async (req, res) => {
  try {
    const { name, email, phone, status } = req.body;
    await pool.query(
      'UPDATE receptionists SET name=?, email=?, phone=?, status=? WHERE id=?',
      [name, email, phone||null, status, req.params.id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete receptionist (Admin)
app.delete('/api/receptionists/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM receptionists WHERE id=?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// ─── OPD Registrations ───────────────────────────────────────

// Create OPD registration
app.post('/api/opd', auth, async (req, res) => {
  try {
    const uhid = 'UHID' + Date.now().toString().slice(-8);
    const token_no = 'T' + Math.floor(Math.random() * 9000 + 1000);
    const {
      full_name, father_husband_name, dob, age, gender, blood_group, marital_status,
      mobile, alternate_mobile, email, address, city, state, pin_code,
      department, doctor_id, visit_type,
      consultation_fee, registration_fee, total_amount, payment_mode, amount_paid, balance,
      height, weight, temperature, pulse_rate, bp_systolic, bp_diastolic, spo2, respiratory_rate,
      chief_complaint, symptoms,
      diabetes, hypertension, heart_disease, asthma, thyroid, previous_surgeries, past_hospitalization,
      current_medications, drug_allergies, food_allergies,
      occupation, emergency_contact_name, emergency_contact_relation, emergency_contact_phone
    } = req.body;
    const reg_date = new Date().toISOString().split('T')[0];
    const reg_time = new Date().toTimeString().split(' ')[0];
    await pool.query(`INSERT INTO opd_registrations (
      uhid,reg_date,reg_time,full_name,father_husband_name,dob,age,gender,blood_group,marital_status,
      mobile,alternate_mobile,email,address,city,state,pin_code,
      department,doctor_id,visit_type,token_no,
      consultation_fee,registration_fee,total_amount,payment_mode,amount_paid,balance,
      height,weight,temperature,pulse_rate,bp_systolic,bp_diastolic,spo2,respiratory_rate,
      chief_complaint,symptoms,diabetes,hypertension,heart_disease,asthma,thyroid,
      previous_surgeries,past_hospitalization,current_medications,drug_allergies,food_allergies,
      occupation,emergency_contact_name,emergency_contact_relation,emergency_contact_phone,created_by
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [uhid,reg_date,reg_time,full_name,father_husband_name||null,dob||null,age||null,
     gender||null,blood_group||null,marital_status||null,mobile||null,alternate_mobile||null,
     email||null,address||null,city||null,state||null,pin_code||null,
     department||null,doctor_id||null,visit_type||'OPD',token_no,
     consultation_fee||0,registration_fee||0,total_amount||0,payment_mode||'Cash',amount_paid||0,balance||0,
     height||null,weight||null,temperature||null,pulse_rate||null,bp_systolic||null,bp_diastolic||null,
     spo2||null,respiratory_rate||null,chief_complaint||null,symptoms||null,
     diabetes?1:0,hypertension?1:0,heart_disease?1:0,asthma?1:0,thyroid?1:0,
     previous_surgeries||null,past_hospitalization||null,current_medications||null,
     drug_allergies||null,food_allergies||null,occupation||null,
     emergency_contact_name||null,emergency_contact_relation||null,emergency_contact_phone||null,
     req.user.id]);
    res.json({ ok: true, uhid, token_no });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get all OPD (Admin)
app.get('/api/opd', auth, async (req, res) => {
  try {
    const [r] = await pool.query(`
      SELECT o.*, d.name as doctor_name 
      FROM opd_registrations o 
      LEFT JOIN doctors d ON o.doctor_id = d.id 
      ORDER BY o.created_at DESC`);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get OPD by doctor
app.get('/api/opd/doctor', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT * FROM opd_registrations WHERE doctor_id = ? ORDER BY created_at DESC',
      [req.user.id]);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update OPD status
app.put('/api/opd/:id/status', auth, async (req, res) => {
  try {
    await pool.query('UPDATE opd_registrations SET status = ? WHERE id = ?',
      [req.body.status, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get single OPD
app.get('/api/opd/:id', auth, async (req, res) => {
  try {
    const [[r]] = await pool.query(
      'SELECT o.*, d.name as doctor_name FROM opd_registrations o LEFT JOIN doctors d ON o.doctor_id = d.id WHERE o.id = ?',
      [req.params.id]);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Patients
app.get('/api/patients', auth, async (req, res) => {
  try { const [r] = await pool.query('SELECT id,name,age,blood_group,phone,email,status FROM patients'); res.json(r); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Appointments
app.get('/api/appointments', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT a.*,p.name as patient_name,d.name as doctor_name FROM appointments a JOIN patients p ON a.patient_id=p.id JOIN doctors d ON a.doctor_id=d.id ORDER BY a.date DESC'
    );
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/appointments/doctor', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT a.*,p.name as patient_name,p.age,p.blood_group FROM appointments a JOIN patients p ON a.patient_id=p.id WHERE a.doctor_id=? ORDER BY a.date DESC',
      [req.user.id]
    );
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/appointments/mine', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT a.*,d.name as doctor_name,d.speciality FROM appointments a JOIN doctors d ON a.doctor_id=d.id WHERE a.patient_id=? ORDER BY a.date DESC',
      [req.user.id]
    );
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/appointments', auth, async (req, res) => {
  try {
    const { doctor_id, date, time, reason } = req.body;
    await pool.query(
      'INSERT INTO appointments (patient_id,doctor_id,date,time,reason) VALUES (?,?,?,?,?)',
      [req.user.id, doctor_id, date, time, reason]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/appointments/:id/status', auth, async (req, res) => {
  try {
    await pool.query('UPDATE appointments SET status=? WHERE id=?', [req.body.status, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Prescriptions
app.get('/api/prescriptions/doctor', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT rx.*,p.name as patient_name FROM prescriptions rx JOIN patients p ON rx.patient_id=p.id WHERE rx.doctor_id=? ORDER BY rx.created_at DESC',
      [req.user.id]
    );
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/prescriptions/mine', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT rx.*,d.name as doctor_name FROM prescriptions rx JOIN doctors d ON rx.doctor_id=d.id WHERE rx.patient_id=? ORDER BY rx.created_at DESC',
      [req.user.id]
    );
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/prescriptions', auth, async (req, res) => {
  try {
    const { patient_id, diagnosis, medicines, notes } = req.body;
    await pool.query(
      'INSERT INTO prescriptions (doctor_id,patient_id,diagnosis,medicines,notes) VALUES (?,?,?,?,?)',
      [req.user.id, patient_id, diagnosis, medicines, notes]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Billing
app.get('/api/billing', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT b.*,p.name as patient_name FROM billing b JOIN patients p ON b.patient_id=p.id ORDER BY b.date DESC'
    );
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/billing/:id/pay', auth, async (req, res) => {
  try {
    await pool.query("UPDATE billing SET status='Paid' WHERE id=?", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Setup
app.get('/api/setup', async (req, res) => {
  try {
    const hash = await bcrypt.hash('password', 10);
    await pool.query('UPDATE doctors SET password = ?', [hash]);
    await pool.query('UPDATE patients SET password = ?', [hash]);
    res.json({ ok: true, hash });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Upload report
app.post('/api/reports/upload', auth, upload.single('file'), async (req, res) => {
  try {
    const { patient_id, test, date } = req.body;
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    await pool.query(
      'INSERT INTO reports (patient_id,test,date,status,file_data,file_name,uploaded_by) VALUES (?,?,?,?,?,?,?)',
      [patient_id, test, date, 'Ready', req.file.buffer, req.file.originalname, req.user.role]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get my reports (Patient)
app.get('/api/reports/mine', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT id,test,date,status,file_name,uploaded_by FROM reports WHERE patient_id=? ORDER BY date DESC',
      [req.user.id]
    );
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get all reports (Admin)
app.get('/api/reports', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT r.id,r.test,r.date,r.status,r.file_name,r.uploaded_by,p.name as patient_name FROM reports r JOIN patients p ON r.patient_id=p.id ORDER BY r.date DESC'
    );
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Download report
app.get('/api/reports/:id/download', async (req, res) => {
  try {
    let token = req.query.token;
    if (!token && req.headers.authorization) {
      token = req.headers.authorization.split(' ')[1];
    }
    if (!token) return res.status(401).json({ error: 'No token' });
    jwt.verify(token, JWT_SECRET);
    const [[report]] = await pool.query('SELECT * FROM reports WHERE id=?', [req.params.id]);
    if (!report) return res.status(404).json({ error: 'Not found' });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${report.file_name}"`);
    res.send(report.file_data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete report
app.delete('/api/reports/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM reports WHERE id=?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Serve frontend
if (fs.existsSync(publicPath)) {
  app.get('*', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
} else {
  app.get('*', (req, res) => res.json({ status: 'MediCare HMS API running' }));
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`MediCare HMS running on port ${PORT}`));
