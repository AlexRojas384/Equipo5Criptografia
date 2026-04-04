CREATE DATABASE casa_monarca CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'monarca_user'@'localhost' IDENTIFIED BY 'TuPasswordSeguro123!';
GRANT ALL PRIVILEGES ON casa_monarca.* TO 'monarca_user'@'localhost';
FLUSH PRIVILEGES;
