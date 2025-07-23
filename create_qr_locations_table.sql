-- Create qr_locations table for GPS tracking
CREATE TABLE IF NOT EXISTS `qr_locations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `qr_id` int(11) NOT NULL,
  `latitude` decimal(10,8) NOT NULL,
  `longitude` decimal(11,8) NOT NULL,
  `location_name` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `qr_id` (`qr_id`),
  KEY `idx_qr_id` (`qr_id`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_updated_at` (`updated_at`),
  CONSTRAINT `fk_qr_locations_qr_id` FOREIGN KEY (`qr_id`) REFERENCES `qr_codes` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add index for better performance
CREATE INDEX idx_qr_locations_lat_lng ON qr_locations(latitude, longitude); 