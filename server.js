require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const publicPath = path.join(__dirname, 'public');
if (fs.existsSync(publicPath)) app.use(express.static(publicPath));

const pool = mysql.createPool({
  host: process.env.MYSQLHOST || process.env.DB_HOST,
  port: parseInt(process.env.MYSQLPORT || process.env.DB_PORT || '3306', 10),
  user: process.env.MYSQLUSER || process.env.DB_USER,
  password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD,
  database: process.env.MYSQLDATABASE || process.env.DB_NAME,
  ssl: false,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_production';
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

function signUser(user) {
  return jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ error: 'Access denied' });
    next();
  };
}

function badRequest(res, message) {
  return res.status(400).json({ error: message });
}

async function loginFromTable(table, role, req, res) {
  try {
    const { email, password } = req.body;
    if (!email || !password) return badRequest(res, 'Email and password are required');
    const [rows] = await pool.query(`SELECT * FROM ${table} WHERE email = ? LIMIT 1`, [email]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    if (user.status && user.status !== 'Active') return res.status(403).json({ error: 'Account is inactive' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signUser({ id: user.id, role, name: user.name });
    res.json({ token, user: { id: user.id, role, name: user.name, email: user.email } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, message: 'API and database connected' });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/admin/login', (req, res) => loginFromTable('admins', 'admin', req, res));
app.post('/api/doctor/login', (req, res) => loginFromTable('doctors', 'doctor', req, res));
app.post('/api/patient/login', (req, res) => loginFromTable('patients', 'patient', req, res));
app.post('/api/receptionist/login', (req, res) => loginFromTable('receptionists', 'receptionist', req, res));

app.post('/api/patient/register', async (req, res) => {
  try {
    const { name, email, password, age, phone, blood } = req.body;
    if (!name || !email || !password) return badRequest(res, 'Name, email and password are required');
    const [exists] = await pool.query('SELECT id FROM patients WHERE email = ? LIMIT 1', [email]);
    if (exists.length) return badRequest(res, 'Email already registered');
    const hash = await bcrypt.hash(password, 10);
    const [r] = await pool.query(
      'INSERT INTO patients (name,email,password,age,phone,blood_group) VALUES (?,?,?,?,?,?)',
      [name.trim(), email.trim(), hash, age || null, phone || null, blood || null]
    );
    const token = signUser({ id: r.insertId, role: 'patient', name: name.trim() });
    res.json({ token, user: { id: r.insertId, role: 'patient', name: name.trim(), email: email.trim() } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/stats', auth, async (req, res) => {
  try {
    const [[{ doctors }]] = await pool.query('SELECT COUNT(*) AS doctors FROM doctors');
    const [[{ patients }]] = await pool.query('SELECT COUNT(*) AS patients FROM patients');
    const [[{ appointments }]] = await pool.query('SELECT COUNT(*) AS appointments FROM appointments');
    const [[{ revenue }]] = await pool.query("SELECT COALESCE(SUM(amount),0) AS revenue FROM billing WHERE status='Paid'");
    res.json({ doctors, patients, appointments, revenue });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/doctors', auth, async (req, res) => {
  try {
    const [r] = await pool.query('SELECT id,name,speciality,phone,email,status,created_at FROM doctors ORDER BY created_at DESC');
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/doctors', auth, requireRole('admin'), async (req, res) => {
  try {
    const { name, speciality, phone, email, password } = req.body;
    if (!name || !email || !password) return badRequest(res, 'Name, email and password are required');
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO doctors (name,speciality,phone,email,password) VALUES (?,?,?,?,?)', [name, speciality || null, phone || null, email, hash]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/doctors/:id', auth, requireRole('admin'), async (req, res) => {
  try {
    const { name, speciality, phone, email, status } = req.body;
    await pool.query('UPDATE doctors SET name=?, speciality=?, phone=?, email=?, status=? WHERE id=?', [name, speciality || null, phone || null, email, status || 'Active', req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/doctors/:id', auth, requireRole('admin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM doctors WHERE id=?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/receptionists', auth, requireRole('admin'), async (req, res) => {
  try {
    const [r] = await pool.query('SELECT id,name,email,phone,status,created_at FROM receptionists ORDER BY created_at DESC');
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/receptionists', auth, requireRole('admin'), async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password) return badRequest(res, 'Name, email and password are required');
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO receptionists (name,email,password,phone) VALUES (?,?,?,?)', [name, email, hash, phone || null]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/receptionists/:id', auth, requireRole('admin'), async (req, res) => {
  try {
    const { name, email, phone, status } = req.body;
    await pool.query('UPDATE receptionists SET name=?, email=?, phone=?, status=? WHERE id=?', [name, email, phone || null, status || 'Active', req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/receptionists/:id', auth, requireRole('admin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM receptionists WHERE id=?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/patients', auth, requireRole('admin', 'doctor', 'receptionist'), async (req, res) => {
  try {
    const [r] = await pool.query('SELECT id,name,age,blood_group,phone,email,status,created_at FROM patients ORDER BY created_at DESC');
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/appointments', auth, requireRole('admin', 'receptionist'), async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT a.*, p.name AS patient_name, d.name AS doctor_name
      FROM appointments a
      JOIN patients p ON a.patient_id = p.id
      JOIN doctors d ON a.doctor_id = d.id
      ORDER BY a.date DESC, a.time DESC`);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/appointments/doctor', auth, requireRole('doctor'), async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT a.*, p.name AS patient_name, p.age, p.blood_group
      FROM appointments a
      JOIN patients p ON a.patient_id = p.id
      WHERE a.doctor_id = ?
      ORDER BY a.date DESC, a.time DESC`, [req.user.id]);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/appointments/mine', auth, requireRole('patient'), async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT a.*, d.name AS doctor_name, d.speciality
      FROM appointments a
      JOIN doctors d ON a.doctor_id = d.id
      WHERE a.patient_id = ?
      ORDER BY a.date DESC, a.time DESC`, [req.user.id]);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/appointments', auth, requireRole('patient'), async (req, res) => {
  try {
    const { doctor_id, date, time, reason } = req.body;
    if (!doctor_id || !date || !time) return badRequest(res, 'Doctor, date and time are required');
    const [conflict] = await pool.query('SELECT id FROM appointments WHERE doctor_id=? AND date=? AND time=? AND status IN (\'Pending\',\'Confirmed\') LIMIT 1', [doctor_id, date, time]);
    if (conflict.length) return badRequest(res, 'Selected slot is already booked');
    await pool.query('INSERT INTO appointments (patient_id,doctor_id,date,time,reason) VALUES (?,?,?,?,?)', [req.user.id, doctor_id, date, time, reason || null]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/appointments/:id/status', auth, requireRole('admin', 'doctor', 'receptionist'), async (req, res) => {
  try {
    const allowed = ['Pending','Confirmed','Completed','Cancelled'];
    if (!allowed.includes(req.body.status)) return badRequest(res, 'Invalid appointment status');
    await pool.query('UPDATE appointments SET status=? WHERE id=?', [req.body.status, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/prescriptions', auth, requireRole('admin', 'receptionist'), async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT rx.*, p.name AS patient_name, d.name AS doctor_name
      FROM prescriptions rx
      JOIN patients p ON rx.patient_id = p.id
      JOIN doctors d ON rx.doctor_id = d.id
      ORDER BY rx.created_at DESC`);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/prescriptions/doctor', auth, requireRole('doctor'), async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT rx.*, p.name AS patient_name
      FROM prescriptions rx
      JOIN patients p ON rx.patient_id = p.id
      WHERE rx.doctor_id = ?
      ORDER BY rx.created_at DESC`, [req.user.id]);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/prescriptions/mine', auth, requireRole('patient'), async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT rx.*, d.name AS doctor_name
      FROM prescriptions rx
      JOIN doctors d ON rx.doctor_id = d.id
      WHERE rx.patient_id = ?
      ORDER BY rx.created_at DESC`, [req.user.id]);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/prescriptions', auth, requireRole('doctor'), async (req, res) => {
  try {
    const { patient_id, diagnosis, medicines, notes } = req.body;
    if (!patient_id) return badRequest(res, 'Patient is required');
    await pool.query('INSERT INTO prescriptions (doctor_id,patient_id,diagnosis,medicines,notes) VALUES (?,?,?,?,?)', [req.user.id, patient_id, diagnosis || null, medicines || null, notes || null]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/billing', auth, requireRole('admin', 'receptionist'), async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT b.*, p.name AS patient_name
      FROM billing b
      JOIN patients p ON b.patient_id = p.id
      ORDER BY b.date DESC, b.created_at DESC`);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/billing/:id/pay', auth, requireRole('admin', 'receptionist'), async (req, res) => {
  try {
    await pool.query("UPDATE billing SET status='Paid' WHERE id=?", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/opd', auth, requireRole('admin', 'receptionist'), async (req, res) => {
  try {
    const uhid = 'UHID' + Date.now().toString().slice(-8);
    const token_no = 'T' + String(Math.floor(Math.random() * 9000 + 1000));
    const {
      fullname, fatherhusbandname, dob, age, gender, bloodgroup, maritalstatus,
      mobile, alternatemobile, email, address, city, state, pincode,
      department, doctorid, visittype,
      consultationfee, registrationfee, totalamount, paymentmode, amountpaid, balance,
      height, weight, temperature, pulserate, bpsystolic, bpdiastolic, spo2, respiratoryrate,
      chiefcomplaint, symptoms,
      diabetes, hypertension, heart_disease, asthma, thyroid,
      previous_surgeries, past_hospitalization, current_medications,
      drug_allergies, food_allergies, occupation,
      emergencycontactname, emergencycontactrelation, emergencycontactphone
    } = req.body;

    if (!fullname) return badRequest(res, 'Patient full name is required');
    const reg_date = new Date().toISOString().split('T')[0];
    const reg_time = new Date().toTimeString().split(' ')[0];
    const [r] = await pool.query(`INSERT INTO opd_registrations (
      uhid,reg_date,reg_time,full_name,father_husband_name,dob,age,gender,blood_group,marital_status,
      mobile,alternate_mobile,email,address,city,state,pin_code,
      department,doctor_id,visit_type,token_no,
      consultation_fee,registration_fee,total_amount,payment_mode,amount_paid,balance,
      height,weight,temperature,pulse_rate,bp_systolic,bp_diastolic,spo2,respiratory_rate,
      chief_complaint,symptoms,diabetes,hypertension,heart_disease,asthma,thyroid,
      previous_surgeries,past_hospitalization,current_medications,drug_allergies,food_allergies,
      occupation,emergency_contact_name,emergency_contact_relation,emergency_contact_phone,created_by
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, [
      uhid, reg_date, reg_time, fullname, fatherhusbandname || null, dob || null, age || null,
      gender || null, bloodgroup || null, maritalstatus || null, mobile || null, alternatemobile || null,
      email || null, address || null, city || null, state || null, pincode || null,
      department || null, doctorid || null, visittype || 'OPD', token_no,
      consultationfee || 0, registrationfee || 0, totalamount || 0, paymentmode || 'Cash', amountpaid || 0, balance || 0,
      height || null, weight || null, temperature || null, pulserate || null, bpsystolic || null, bpdiastolic || null,
      spo2 || null, respiratoryrate || null, chiefcomplaint || null, symptoms || null,
      diabetes ? 1 : 0, hypertension ? 1 : 0, heart_disease ? 1 : 0, asthma ? 1 : 0, thyroid ? 1 : 0,
      previous_surgeries || null, past_hospitalization || null, current_medications || null,
      drug_allergies || null, food_allergies || null, occupation || null,
      emergencycontactname || null, emergencycontactrelation || null, emergencycontactphone || null,
      req.user.id
    ]);
    res.json({ ok: true, uhid, token_no, id: r.insertId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/opd', auth, requireRole('admin', 'receptionist'), async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT o.*, d.name AS doctor_name FROM opd_registrations o
      LEFT JOIN doctors d ON o.doctor_id = d.id
      ORDER BY o.created_at DESC`);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/opd/doctor', auth, requireRole('doctor'), async (req, res) => {
  try {
    const [r] = await pool.query(`SELECT o.*, d.name AS doctor_name, d.speciality
      FROM opd_registrations o
      LEFT JOIN doctors d ON o.doctor_id = d.id
      WHERE o.doctor_id = ?
      ORDER BY o.created_at DESC`, [req.user.id]);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/opd/:id/status', auth, requireRole('admin', 'receptionist', 'doctor'), async (req, res) => {
  try {
    const allowed = ['Registered','Checked-In','Consulted','Completed','Cancelled'];
    if (!allowed.includes(req.body.status)) return badRequest(res, 'Invalid OPD status');
    await pool.query('UPDATE opd_registrations SET status=? WHERE id=?', [req.body.status, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/opd/:id/consult', auth, requireRole('doctor'), async (req, res) => {
  try {
    const { diagnosis, prescription, notes } = req.body;
    await pool.query('UPDATE opd_registrations SET diagnosis=?, prescription=?, notes=?, status=\'Consulted\' WHERE id=?', [diagnosis || null, prescription || null, notes || null, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/opd/:id', auth, requireRole('admin', 'receptionist', 'doctor'), async (req, res) => {
  try {
    const [[r]] = await pool.query(`SELECT o.*, d.name AS doctor_name
      FROM opd_registrations o
      LEFT JOIN doctors d ON o.doctor_id = d.id
      WHERE o.id = ?`, [req.params.id]);
    if (!r) return res.status(404).json({ error: 'OPD record not found' });
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reports/upload', auth, requireRole('admin', 'doctor', 'receptionist'), upload.single('file'), async (req, res) => {
  try {
    const { patient_id, test, date } = req.body;
    if (!patient_id || !test || !date) return badRequest(res, 'Patient, test and date are required');
    if (!req.file) return badRequest(res, 'No file uploaded');

    await pool.query(
      'INSERT INTO reports (patient_id,test,date,status,file_data,file_name,file_mime,file_size,uploaded_by) VALUES (?,?,?,?,?,?,?,?,?)',
      [
        patient_id,
        test,
        date,
        'Ready',
        req.file.buffer,
        req.file.originalname,
        req.file.mimetype || 'application/octet-stream',
        req.file.size || 0,
        req.user.role
      ]
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/reports/mine', auth, requireRole('patient'), async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT id,test,date,status,file_name,file_mime,file_size,uploaded_by,created_at FROM reports WHERE patient_id=? ORDER BY date DESC, created_at DESC',
      [req.user.id]
    );
    res.json(r);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/reports', auth, requireRole('admin', 'doctor', 'receptionist'), async (req, res) => {
  try {
    const [r] = await pool.query(`
      SELECT r.id,r.test,r.date,r.status,r.file_name,r.file_mime,r.file_size,r.uploaded_by,r.created_at,p.name AS patient_name
      FROM reports r
      JOIN patients p ON r.patient_id=p.id
      ORDER BY r.date DESC, r.created_at DESC
    `);
    res.json(r);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/reports/:id/download', auth, async (req, res) => {
  try {
    const [[report]] = await pool.query('SELECT * FROM reports WHERE id=?', [req.params.id]);
    if (!report) return res.status(404).json({ error: 'Not found' });

    if (req.user.role === 'patient') {
      const [[mine]] = await pool.query(
        'SELECT id FROM reports WHERE id=? AND patient_id=?',
        [req.params.id, req.user.id]
      );
      if (!mine) return res.status(403).json({ error: 'Access denied' });
    }

    res.setHeader('Content-Type', report.file_mime || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${report.file_name}"`);
    res.send(report.file_data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/reports/:id', auth, requireRole('admin', 'doctor', 'receptionist'), async (req, res) => {
  try {
    await pool.query('DELETE FROM reports WHERE id=?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

if (fs.existsSync(publicPath)) {
  app.get('*', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
} else {
  app.get('*', (req, res) => res.json({ status: 'MediCare HMS API running' }));
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`MediCare HMS running on port ${PORT}`));
