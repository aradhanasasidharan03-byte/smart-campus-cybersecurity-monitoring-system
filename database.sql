CREATE DATABASE IF NOT EXISTS smart_campus_security
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE smart_campus_security;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(160) NOT NULL,
  password_hash VARCHAR(256) NOT NULL,
  role VARCHAR(24) NOT NULL DEFAULT 'Viewer',
  created_at DATETIME NOT NULL,
  CONSTRAINT ck_user_role CHECK (role IN ('Admin', 'Security Analyst', 'Viewer')),
  UNIQUE INDEX ix_users_email (email),
  INDEX ix_users_role (role)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS departments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  description VARCHAR(240) NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS devices (
  id INT AUTO_INCREMENT PRIMARY KEY,
  asset_tag VARCHAR(32) NOT NULL,
  name VARCHAR(120) NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  mac_address VARCHAR(17) NOT NULL,
  device_type VARCHAR(48) NOT NULL,
  department_id INT NOT NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'Online',
  risk_score INT NOT NULL DEFAULT 0,
  last_seen DATETIME NOT NULL,
  created_at DATETIME NOT NULL,
  CONSTRAINT ck_device_risk_score CHECK (risk_score BETWEEN 0 AND 100),
  CONSTRAINT ck_device_status CHECK (status IN ('Online', 'Offline', 'Monitoring')),
  CONSTRAINT fk_devices_department FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE CASCADE,
  UNIQUE INDEX ix_devices_asset_tag (asset_tag),
  INDEX ix_devices_ip_address (ip_address),
  INDEX ix_devices_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_alerts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  alert_code VARCHAR(24) NOT NULL,
  threat_type VARCHAR(64) NOT NULL,
  device_id INT NULL,
  ip_address VARCHAR(45) NOT NULL,
  severity VARCHAR(16) NOT NULL,
  description VARCHAR(500) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'New',
  created_at DATETIME NOT NULL,
  resolved_at DATETIME NULL,
  CONSTRAINT ck_alert_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  CONSTRAINT ck_alert_status CHECK (status IN ('New', 'Investigating', 'Resolved')),
  CONSTRAINT fk_alerts_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL,
  UNIQUE INDEX ix_security_alerts_alert_code (alert_code),
  INDEX ix_security_alerts_threat_type (threat_type),
  INDEX ix_security_alerts_severity (severity),
  INDEX ix_security_alerts_status (status),
  INDEX ix_security_alerts_created_at (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  device_id INT NULL,
  actor VARCHAR(120) NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  description VARCHAR(500) NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  severity VARCHAR(16) NOT NULL DEFAULT 'LOW',
  created_at DATETIME NOT NULL,
  CONSTRAINT fk_logs_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_logs_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL,
  INDEX ix_security_logs_event_type (event_type),
  INDEX ix_security_logs_severity (severity),
  INDEX ix_security_logs_created_at (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS threat_events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  device_id INT NULL,
  threat_type VARCHAR(64) NOT NULL,
  source_ip VARCHAR(45) NOT NULL,
  severity VARCHAR(16) NOT NULL,
  description VARCHAR(500) NOT NULL,
  event_data JSON NOT NULL,
  created_at DATETIME NOT NULL,
  CONSTRAINT fk_threat_events_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL,
  INDEX ix_threat_events_threat_type (threat_type),
  INDEX ix_threat_events_severity (severity),
  INDEX ix_threat_events_created_at (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS reports (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(160) NOT NULL,
  report_type VARCHAR(48) NOT NULL,
  created_by INT NULL,
  summary JSON NOT NULL,
  created_at DATETIME NOT NULL,
  CONSTRAINT fk_reports_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

INSERT IGNORE INTO departments (name, description) VALUES
  ('IT Services', 'Campus infrastructure and support'),
  ('Research Labs', 'Teaching and research environments'),
  ('Library', 'Library workstations and services'),
  ('Student Housing', 'Residence network and IoT'),
  ('Administration', 'Administrative systems');

-- On first application startup, run.py creates the schema if needed and seeds
-- demo users, 12 devices, 9 alerts, 12 logs, threat events, and a sample report.
