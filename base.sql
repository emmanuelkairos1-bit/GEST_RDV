-- GEST_RDV : script à importer dans phpMyAdmin (onglet Importer)
SET NAMES utf8mb4;
CREATE DATABASE IF NOT EXISTS gest_rdv CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE gest_rdv;

CREATE TABLE IF NOT EXISTS entreprises (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  nom VARCHAR(150) NOT NULL,
  adresse VARCHAR(255) NOT NULL DEFAULT '',
  telephone VARCHAR(30) NOT NULL DEFAULT '',
  email VARCHAR(150) NOT NULL DEFAULT '',
  couleur CHAR(7) NOT NULL DEFAULT '#6c5ce7'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS services (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  nom VARCHAR(120) NOT NULL UNIQUE,
  description VARCHAR(500) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS utilisateurs (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  nom VARCHAR(120) NOT NULL,
  email VARCHAR(150) NOT NULL UNIQUE,
  mot_de_passe VARCHAR(255) NOT NULL,
  role ENUM('super_admin','agent') NOT NULL DEFAULT 'agent',
  service_id INT UNSIGNED NULL,
  CONSTRAINT fk_user_service FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS rendez_vous (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  code_suivi VARCHAR(30) NOT NULL UNIQUE,
  nom VARCHAR(80) NOT NULL,
  prenom VARCHAR(80) NOT NULL,
  telephone VARCHAR(25) NOT NULL,
  email VARCHAR(150) NOT NULL,
  service_id INT UNSIGNED NOT NULL,
  date_souhaitee DATE NOT NULL,
  motif TEXT NOT NULL,
  statut ENUM('En attente','Validé','Reporté','Refusé') NOT NULL DEFAULT 'En attente',
  motif_report_refus TEXT NULL,
  date_creation TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_statut (statut), INDEX idx_date (date_souhaitee), INDEX idx_service (service_id),
  CONSTRAINT fk_rdv_service FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
