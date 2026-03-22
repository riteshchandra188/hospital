CREATE DATABASE IF NOT EXISTS medicare_hms;
USE medicare_hms;

CREATE TABLE IF NOT EXISTS doctors (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(120) NOT NULL,
  speciality VARCHAR(100),
  phone      VARCHAR(20),
  email      VARCHAR(120) UNIQUE NOT NULL,
  password   VARCHAR(255) NOT NULL,
  status     ENUM('Active','Inactive') DEFAULT 'Active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS patients (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(120) NOT NULL,
  email       VARCHAR(120) UNIQUE NOT NULL,
  password    VARCHAR(255) NOT NULL,
  age         INT,
  blood_group VARCHAR(5),
  phone       VARCHAR(20),
  status      ENUM('Active','Inactive') DEFAULT 'Active',
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS appointments (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  patient_id INT NOT NULL,
  doctor_id  INT NOT NULL,
  date       DATE NOT NULL,
  time       TIME NOT NULL,
  reason     TEXT,
  status     ENUM('Pending','Confirmed','Completed','Cancelled') DEFAULT 'Pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
  FOREIGN KEY (doctor_id)  REFERENCES doctors(id)  ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS prescriptions (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  doctor_id  INT NOT NULL,
  patient_id INT NOT NULL,
  diagnosis  TEXT,
  medicines  TEXT,
  notes      TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (doctor_id)  REFERENCES doctors(id)  ON DELETE CASCADE,
  FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS billing (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  patient_id INT NOT NULL,
  amount     DECIMAL(10,2) NOT NULL,
  type       VARCHAR(80),
  date       DATE NOT NULL,
  status     ENUM('Pending','Paid') DEFAULT 'Pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE
);

INSERT IGNORE INTO doctors (name, speciality, phone, email, password) VALUES
('Dr. Priya Sharma', 'Cardiologist',  '9811001100', 'priya@medicare.com',  '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'),
('Dr. Rohan Mehta',  'Neurologist',   '9822002200', 'rohan@medicare.com',  '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'),
('Dr. Anjali Singh', 'Pediatrician',  '9833003300', 'anjali@medicare.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi');
