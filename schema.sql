CREATE DATABASE IF NOT EXISTS medicare_hms;
USE medicare_hms;

CREATE TABLE IF NOT EXISTS admins (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(120) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  phone VARCHAR(20),
  status ENUM('Active','Inactive') NOT NULL DEFAULT 'Active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS doctors (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  speciality VARCHAR(100),
  phone VARCHAR(20),
  email VARCHAR(120) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  status ENUM('Active','Inactive') NOT NULL DEFAULT 'Active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS receptionists (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(120) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  phone VARCHAR(20),
  status ENUM('Active','Inactive') NOT NULL DEFAULT 'Active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS patients (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(120) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  age INT,
  blood_group VARCHAR(5),
  phone VARCHAR(20),
  gender VARCHAR(20),
  address TEXT,
  status ENUM('Active','Inactive') NOT NULL DEFAULT 'Active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS appointments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  patient_id INT NOT NULL,
  doctor_id INT NOT NULL,
  date DATE NOT NULL,
  time TIME NOT NULL,
  reason TEXT,
  status ENUM('Pending','Confirmed','Completed','Cancelled') NOT NULL DEFAULT 'Pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_appointments_patient FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
  CONSTRAINT fk_appointments_doctor FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS prescriptions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  doctor_id INT NOT NULL,
  patient_id INT NOT NULL,
  diagnosis TEXT,
  medicines TEXT,
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_prescriptions_doctor FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE CASCADE,
  CONSTRAINT fk_prescriptions_patient FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS billing (
  id INT AUTO_INCREMENT PRIMARY KEY,
  patient_id INT NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  type VARCHAR(80),
  date DATE NOT NULL,
  status ENUM('Pending','Paid') NOT NULL DEFAULT 'Pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_billing_patient FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
  id INT AUTO_INCREMENT PRIMARY KEY,
  patient_id INT NOT NULL,
  test VARCHAR(150) NOT NULL,
  date DATE NOT NULL,
  status ENUM('Pending','Ready') NOT NULL DEFAULT 'Ready',
  file_name VARCHAR(255) NOT NULL,
  file_mime VARCHAR(120) DEFAULT 'application/octet-stream',
  file_data LONGBLOB NOT NULL,
  uploaded_by VARCHAR(30),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_reports_patient FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS opd_registrations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  uhid VARCHAR(30) NOT NULL UNIQUE,
  reg_date DATE NOT NULL,
  reg_time TIME NOT NULL,
  full_name VARCHAR(120) NOT NULL,
  father_husband_name VARCHAR(120),
  dob DATE,
  age INT,
  gender VARCHAR(20),
  blood_group VARCHAR(5),
  marital_status VARCHAR(30),
  mobile VARCHAR(20),
  alternate_mobile VARCHAR(20),
  email VARCHAR(120),
  address TEXT,
  city VARCHAR(80),
  state VARCHAR(80),
  pin_code VARCHAR(15),
  department VARCHAR(100),
  doctor_id INT,
  visit_type VARCHAR(30) DEFAULT 'OPD',
  token_no VARCHAR(20) NOT NULL,
  consultation_fee DECIMAL(10,2) DEFAULT 0,
  registration_fee DECIMAL(10,2) DEFAULT 0,
  total_amount DECIMAL(10,2) DEFAULT 0,
  payment_mode VARCHAR(30) DEFAULT 'Cash',
  amount_paid DECIMAL(10,2) DEFAULT 0,
  balance DECIMAL(10,2) DEFAULT 0,
  height VARCHAR(20),
  weight VARCHAR(20),
  temperature VARCHAR(20),
  pulse_rate VARCHAR(20),
  bp_systolic VARCHAR(20),
  bp_diastolic VARCHAR(20),
  spo2 VARCHAR(20),
  respiratory_rate VARCHAR(20),
  chief_complaint TEXT,
  symptoms TEXT,
  diabetes TINYINT(1) DEFAULT 0,
  hypertension TINYINT(1) DEFAULT 0,
  heart_disease TINYINT(1) DEFAULT 0,
  asthma TINYINT(1) DEFAULT 0,
  thyroid TINYINT(1) DEFAULT 0,
  previous_surgeries TEXT,
  past_hospitalization TEXT,
  current_medications TEXT,
  drug_allergies TEXT,
  food_allergies TEXT,
  occupation VARCHAR(100),
  emergency_contact_name VARCHAR(120),
  emergency_contact_relation VARCHAR(80),
  emergency_contact_phone VARCHAR(20),
  diagnosis TEXT,
  prescription TEXT,
  notes TEXT,
  status ENUM('Registered','Checked-In','Consulted','Completed','Cancelled') NOT NULL DEFAULT 'Registered',
  created_by INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_opd_doctor FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE SET NULL
);

INSERT IGNORE INTO admins (name, email, password, phone) VALUES
('Admin', 'admin@medicare.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', '9999999999');

INSERT IGNORE INTO doctors (name, speciality, phone, email, password) VALUES
('Dr. Priya Sharma', 'Cardiologist', '9811001100', 'priya@medicare.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'),
('Dr. Rohan Mehta', 'Neurologist', '9822002200', 'rohan@medicare.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'),
('Dr. Anjali Singh', 'Pediatrician', '9833003300', 'anjali@medicare.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi');

INSERT IGNORE INTO receptionists (name, email, password, phone) VALUES
('Reception Desk', 'reception@medicare.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', '9876543210');
