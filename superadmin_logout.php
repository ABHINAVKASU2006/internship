<?php
session_start();

// Clear all sessions
session_unset();
session_destroy();

// Redirect to main login
header("Location: home.php");
exit();
?>
