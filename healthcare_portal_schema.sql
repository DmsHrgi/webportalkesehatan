-- Database schema for Healthcare Patient Portal
-- Based on journal recommendations for better patient understanding

-- Create database
CREATE DATABASE IF NOT EXISTS healthcare_portal;
USE healthcare_portal;

-- Users table (Pasien)
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    age_group ENUM('18-34', '35-49', '50-64', '65-74', '≥75') NOT NULL,
    birth_sex ENUM('Male', 'Female') NOT NULL,
    race_ethnicity VARCHAR(50),
    education VARCHAR(50),
    numeracy_score ENUM('Very easy', 'Easy', 'Hard') NOT NULL,
    health_literacy_level ENUM('High', 'Medium', 'Low') NOT NULL,
    preferred_access_mode ENUM('Website only', 'App only', 'Both') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Health profiles table (Profil Kesehatan)
CREATE TABLE health_profiles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    general_health ENUM('Excellent', 'Very good', 'Good', 'Fair', 'Poor'),
    confidence_manage_health ENUM('Completely', 'Very', 'Somewhat', 'Little', 'Not at all'),
    has_deafness BOOLEAN DEFAULT FALSE,
    has_diabetes BOOLEAN DEFAULT FALSE,
    has_hypertension BOOLEAN DEFAULT FALSE,
    has_heart_condition BOOLEAN DEFAULT FALSE,
    has_lung_disease BOOLEAN DEFAULT FALSE,
    has_depression BOOLEAN DEFAULT FALSE,
    has_cancer_history BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Provider communications table (Komunikasi dengan Provider)
CREATE TABLE provider_communications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    communication_score TINYINT CHECK (communication_score BETWEEN 1 AND 7),
    provider_encouraged_portal BOOLEAN DEFAULT FALSE,
    visit_frequency ENUM('Rarely', 'Occasionally', 'Frequently'),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Portal usage logs (Log Penggunaan Portal)
CREATE TABLE portal_usage_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    access_mode ENUM('Website', 'Mobile App', 'Both') NOT NULL,
    feature_used ENUM('View Results', 'View Notes', 'Download', 'Send to Third Party') NOT NULL,
    session_duration INT COMMENT 'Duration in seconds',
    ease_of_understanding ENUM('Very easy', 'Somewhat easy', 'Somewhat difficult', 'Very difficult'),
    accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Content feedback table (Umpan Balik Konten)
CREATE TABLE content_feedback (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    content_type ENUM('Test Results', 'Clinical Notes', 'Appointments', 'Medications') NOT NULL,
    clarity_rating TINYINT CHECK (clarity_rating BETWEEN 1 AND 5),
    suggestions TEXT,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Interface preferences (Preferensi Antarmuka)
CREATE TABLE interface_preferences (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    font_size ENUM('Small', 'Medium', 'Large') DEFAULT 'Medium',
    color_scheme ENUM('Default', 'High Contrast', 'Dark Mode') DEFAULT 'Default',
    language_preference ENUM('English', 'Spanish', 'Other') DEFAULT 'English',
    simplification_level ENUM('Standard', 'Simplified', 'Detailed') DEFAULT 'Standard',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create indexes for better performance
CREATE INDEX idx_users_numeracy ON users(numeracy_score);
CREATE INDEX idx_users_age_group ON users(age_group);
CREATE INDEX idx_health_profiles_user ON health_profiles(user_id);
CREATE INDEX idx_portal_usage_user ON portal_usage_logs(user_id);

-- Query to identify users who might need assistance
-- This is the query from your requirements
CREATE VIEW users_needing_assistance AS
SELECT u.id, u.age_group, u.numeracy_score, u.preferred_access_mode,
       h.general_health, p.communication_score
FROM users u
LEFT JOIN health_profiles h ON u.id = h.user_id
LEFT JOIN provider_communications p ON u.id = p.user_id
WHERE u.numeracy_score = 'Hard'
   OR u.age_group IN ('65-74', '≥75')
   OR p.communication_score < 4
ORDER BY u.numeracy_score DESC;
