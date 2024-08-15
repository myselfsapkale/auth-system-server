# ************************************************************
# Sequel Ace SQL dump
# Version 20067
#
# https://sequel-ace.com/
# https://github.com/Sequel-Ace/Sequel-Ace
#
# Host: 127.0.0.1 (MySQL 9.0.0)
# Database: bus-ticket-db
# Generation Time: 2024-08-11 21:30:29 +0000
# ************************************************************


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
SET NAMES utf8mb4;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE='NO_AUTO_VALUE_ON_ZERO', SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


# Dump of table auth_access_token
# ------------------------------------------------------------

DROP TABLE IF EXISTS `auth_access_token`;

CREATE TABLE `auth_access_token` (
  `id` int NOT NULL AUTO_INCREMENT,
  `access_token` varchar(255) NOT NULL,
  `refresh_token_id` int NOT NULL,
  `created_on` varchar(255) NOT NULL,
  `updated_on` varchar(255) NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `refresh_token_id` (`refresh_token_id`),
  CONSTRAINT `auth_access_token_ibfk_1` FOREIGN KEY (`refresh_token_id`) REFERENCES `auth_refresh_token` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;



# Dump of table auth_refresh_token
# ------------------------------------------------------------

DROP TABLE IF EXISTS `auth_refresh_token`;

CREATE TABLE `auth_refresh_token` (
  `id` int NOT NULL AUTO_INCREMENT,
  `refresh_token` varchar(255) NOT NULL,
  `user_id` int NOT NULL,
  `created_on` varchar(255) NOT NULL,
  `updated_on` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_refresh_token` (`refresh_token`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `auth_refresh_token_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;



# Dump of table users
# ------------------------------------------------------------

DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_first_name` varchar(45) NOT NULL,
  `user_last_name` varchar(45) NOT NULL,
  `user_email` varchar(45) NOT NULL,
  `user_phone` varchar(15) DEFAULT NULL,
  `user_type` varchar(45) NOT NULL,
  `provider` varchar(50) NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  `created_on` varchar(255) NOT NULL,
  `updated_on` varchar(255) NOT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_phone_UNIQUE` (`user_phone`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;




/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
