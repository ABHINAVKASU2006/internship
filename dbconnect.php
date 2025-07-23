<?php
$host = "localhost";
$username = "root";
$password = "123456"; 
$database = "addwise";

$conn = new mysqli($host, $username, $password, $database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
 