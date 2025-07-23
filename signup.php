<?php
/*include 'dbconnect.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $name     = $_POST['name'];
    $email    = $_POST['email'];
    $mobile   = $_POST['mobile'];
    $age      = $_POST['age'];
    $gender   = $_POST['gender'];
    $password = $_POST['password'];
    $role     = $_POST['role'];

    // Check for admin secret code if role is admin
    if ($role === 'admin') {
        $admin_code = $_POST['admin_code'] ?? '';
        $secret_key = 'ADMIN123'; // Change this to your real secret key

        if ($admin_code !== $secret_key) {
            die("Invalid admin secret code. Access denied.");
        }
    }

    // Check if email already exists
    $check = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $check->bind_param("s", $email);
    $check->execute();
    $check->store_result();

    if ($check->num_rows > 0) {
        die("Email already registered.");
    }

    // Hash password and insert
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $conn->prepare("INSERT INTO users (name, email, mobile, age, gender, password, role) VALUES (?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssisss", $name, $email, $mobile, $age, $gender, $hashedPassword, $role);

    if ($stmt->execute()) {
        echo "Signup successful! You can now <a href='index3.html'>login</a>.";
    } else {
        echo "Error: " . $stmt->error;
    }
}*/
?>
