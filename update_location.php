<?php
require 'dbconnect.php'; // connect to DB

$data = json_decode(file_get_contents('php://input'), true);
$qr_id = $data['qr_id'];
$latitude = $data['latitude'];
$longitude = $data['longitude'];

// Reverse geocode using a service if needed to get `location_name`
$location_name = null;

$stmt = $pdo->prepare("
    INSERT INTO qr_locations (qr_id, latitude, longitude, location_name)
    VALUES (:qr_id, :lat, :lon, :location)
    ON DUPLICATE KEY UPDATE
        latitude = VALUES(latitude),
        longitude = VALUES(longitude),
        location_name = VALUES(location_name),
        updated_at = CURRENT_TIMESTAMP
");
$stmt->execute([
    ':qr_id' => $qr_id,
    ':lat' => $latitude,
    ':lon' => $longitude,
    ':location' => $location_name
]);

echo json_encode(['status' => 'success']);
?>
