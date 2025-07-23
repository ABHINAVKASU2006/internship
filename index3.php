<?php
session_start();

if (isset($_SESSION['otp_verified'])) {
    unset($_SESSION['otp_verified']);
}
unset(
    $_SESSION['reset_email'],
    $_SESSION['reset_otp'],
    $_SESSION['reset_otp_verified']
);
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

if (isset($_SESSION['is_logged_in'])) {
    if ($_SESSION['role'] === 'Admin') {
        header("Location: admin_dashboard.php");
    } else if ($_SESSION['role'] === 'User') {
        header("Location: user_dashboard.php");
    }
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Bootstrap Auth Page</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    :root {
      --primary: #3B82F6;
      --secondary: #F1F5F9;
      --accent: #FBBF24;
      --background: #F8FAFC;
      --surface: #FFFFFF;
      --text: #232946;
      --muted: #64748B;
      --border: #E5E7EB;
      --shadow: 0 8px 32px rgba(59, 130, 246, 0.10);
    }

    body {
      background: linear-gradient(120deg, var(--primary) 0%, var(--secondary) 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      color: var(--text);
    }

    .glass {
      background: var(--surface);
      border-radius: 20px;
      box-shadow: var(--shadow);
      border: 1.5px solid var(--border);
      padding: 48px 40px;
      margin: 0 auto;
      max-width: 420px;
      width: 100%;
      transition: box-shadow 0.3s, border-color 0.3s;
      backdrop-filter: blur(8px);
    }

    .glass:hover {
      box-shadow: 0 12px 40px rgba(59, 130, 246, 0.18);
      border-color: var(--primary);
    }

    .fw-bold {
      color: var(--primary);
      font-size: 2.1rem;
      font-weight: 700;
      letter-spacing: 1.2px;
      margin-bottom: 10px;
    }

    .toggle-btn {
      color: var(--muted);
      font-weight: 600;
      font-size: 1.08rem;
      transition: color 0.2s;
      cursor: pointer;
      padding: 2px 8px;
      border-radius: 6px;
    }

    .toggle-btn.active, .toggle-btn:hover {
      color: var(--primary);
      background: var(--secondary);
      text-decoration: none;
    }

    .form-label {
      color: var(--muted);
      font-weight: 600;
      margin-bottom: 7px;
      font-size: 15px;
    }

    .form-control {
      background: var(--secondary);
      border: 1.5px solid var(--border);
      border-radius: 12px;
      padding: 13px 18px;
      color: var(--text);
      font-size: 16px;
      transition: border-color 0.3s, box-shadow 0.3s;
      box-shadow: none;
    }

    .form-control:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.10);
      outline: none;
      background: #fff;
    }

    .btn-3d, .btn-primary {
      background: linear-gradient(90deg, var(--primary), #2563EB);
      border: none;
      border-radius: 12px;
      padding: 14px;
      font-size: 18px;
      font-weight: 600;
      letter-spacing: 0.5px;
      transition: all 0.2s;
      box-shadow: 0 4px 16px rgba(59, 130, 246, 0.10);
      color: #fff;
    }

    .btn-3d:hover, .btn-primary:hover {
      background: linear-gradient(90deg, #2563EB, var(--primary));
      transform: translateY(-2px) scale(1.03);
      box-shadow: 0 8px 24px rgba(59, 130, 246, 0.16);
      color: #fff;
    }

    .btn-google {
      background: #fff;
      color: var(--primary);
      border: 1.5px solid var(--primary);
      border-radius: 12px;
      padding: 10px 0;
      font-weight: 600;
      width: 100%;
      margin-top: 10px;
      transition: background 0.2s, color 0.2s, border-color 0.2s;
    }

    .btn-google:hover {
      background: var(--primary);
      color: #fff;
      border-color: #2563EB;
    }

    .forgot-password {
      color: var(--primary);
      font-weight: 500;
      font-size: 15px;
      text-decoration: none;
      transition: color 0.2s;
    }

    .forgot-password:hover {
      color: var(--accent);
      text-decoration: underline;
    }

    #admin-secret-box {
      background: var(--secondary);
      border-radius: 12px;
      padding: 12px;
      margin-bottom: 15px;
      border-left: 4px solid var(--primary);
    }

    @media (max-width: 991px) {
      .glass {
        padding: 32px 10px;
        max-width: 95vw;
      }
    }

    @media (max-width: 600px) {
      .glass {
        padding: 18px 3px;
        max-width: 99vw;
      }
      .fw-bold {
        font-size: 1.3rem;
      }
    }
  </style>
</head>
<body class="d-flex align-items-center justify-content-center py-5">

  <!-- Rest of your content -->
  <div class="container glass col-md-8 col-lg-6">
    <div class="row">
      <div class="col-md-5 text-center mb-4 mb-md-0 d-flex flex-column justify-content-center">
        <h2 class="fw-bold">Welcome!</h2>
        <p>Join us for Exploring the world that you have ever seen</p>
        <div>
          <span class="toggle-btn me-3" id="show-login" style="cursor: pointer;">Login</span> | 
          <span class="toggle-btn ms-3" id="show-signup" style="cursor: pointer;">Signup</span>
        </div>
      </div>
      <div class="col-md-7">
 <a href="home.php" class="position-absolute top-0 start-0 m-3 btn" style="
   /* Using your dark teal color */
    color: var(--dark);;
    border: none;
    border-radius: 12px;
    padding: 8px 15px;
    font-weight: 500;
    transition: all 0.3s;
">
    <i class="fas fa-arrow-left"></i> <-- Back to Home
</a>
        <form id="login-form" action="login.php" method="POST">
          <h4 class="mb-3">Login</h4>
          <div class="mb-3">
            <select class="form-select" name="role" required>
              <option value="">Select Role</option>
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div class="mb-3">
            <input type="email" class="form-control" name="email" placeholder="Email" required
              pattern="[a-zA-Z0-9._%+-]+@gmail\.com$" 
              title="Email must be in the format: example@gmail.com" />
          </div>
          <div class="mb-3">
            <input type="password" class="form-control" name="password" placeholder="Password" required
              pattern="^(?=[A-Za-z0-9])(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"
              title="Password must be at least 8 characters, contain a letter, a number, a special character, start with a letter or number, and contain no spaces." />
            <div class="text-end mt-1">
              <button type="button" id="forgot-password-btn" class="btn btn-link p-0 forgot-password">Forgot Password?</button>
            </div>
          </div>
          <button type="submit" class="btn btn-3d w-100">Login</button>
          <button type="button" class="btn-google mt-2" aria-label="Continue with Google">
            Continue with Google
          </button>
        </form>
        <form id="signup-form" class="d-none" action="register.php" method="POST">
          <h4 class="mb-3">Signup</h4>
          <div class="mb-3">
            <input type="text" class="form-control" name="name" placeholder="Full Name" required
              pattern="^[A-Za-z ]+$"
              title="Name must contain only alphabets and spaces." />
          </div>
          <div class="mb-3">
            <input type="email" class="form-control" name="email" placeholder="Email" required
              pattern="[a-zA-Z0-9._%+-]+@gmail\.com$" 
              title="Email must end with @gmail.com" />
          </div>
          <div class="mb-3">
            <input type="tel" class="form-control" name="mobile" placeholder="Mobile Number" required 
              pattern="[0-9]{10}" 
              title="Mobile number must be exactly 10 digits" />
          </div>
          <div class="mb-3">
            <input type="number" class="form-control" name="age" placeholder="Age" required min="1" max="120" />
          </div>
          <div class="mb-3">
            <select class="form-select" name="gender" required>
              <option value="">Select Gender</option>
              <option>Male</option>
              <option>Female</option>
              <option>Other</option>
            </select>
          </div>
          <div class="mb-3">
            <select class="form-select" name="role" id="signup-role" required>
              <option value="">Select Role</option>
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div class="mb-3" id="admin-secret-box" style="display: none;">
            <input type="password" class="form-control" name="admin_code" id="admin-code" placeholder="Enter Admin Secret Code" />
          </div>
          <div class="mb-3">
            <input type="password" class="form-control" name="password" placeholder="Password" id="signup-password" required
              pattern="^(?=[A-Za-z0-9])(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"
              title="Password must be at least 8 characters, contain a letter, a number, a special character, start with a letter or number, and contain no spaces." />
          </div>
          <div class="mb-3">
            <input type="password" class="form-control" placeholder="Confirm Password" id="confirm-password" required />
          </div>
          <button type="submit" class="btn btn-3d w-100">Signup</button>
          <button type="button" class="btn-google mt-2" aria-label="Continue with Google">
            Continue with Google
          </button>
        </form>

        <!-- Inside the right column, after the signup form -->
<div class="text-center mt-4">
    <a href="superadmin_login.php" class="btn btn-warning">
        <i class="fas fa-star"></i> Super Admin Login
    </a>
</div>

      </div>
    </div>
  </div>

  <script>

// Block back navigation
history.pushState(null, null, location.href);
window.onpopstate = function() {
    history.go(1);
};

// Force fresh page load on navigation
window.addEventListener('pageshow', function(event) {
    if (event.persisted || performance.navigation.type === 2) {
        window.location.reload();
    }
});

// Clear reset-related session variables
sessionStorage.removeItem('reset_in_progress');

    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const showLogin = document.getElementById('show-login');
    const showSignup = document.getElementById('show-signup');

    showLogin.onclick = () => {
      loginForm.classList.remove('d-none');
      signupForm.classList.add('d-none');
    };

    showSignup.onclick = () => {
      signupForm.classList.remove('d-none');
      loginForm.classList.add('d-none');
    };

    document.getElementById('signup-role').addEventListener('change', function () {
      const adminSecretBox = document.getElementById('admin-secret-box');
      if (this.value === 'admin') {
        adminSecretBox.style.display = 'block';
        document.getElementById('admin-code').setAttribute('required', 'required');
      } else {
        adminSecretBox.style.display = 'none';
        document.getElementById('admin-code').removeAttribute('required');
      }
    });

    signupForm.addEventListener('submit', function (e) {
      const password = document.getElementById('signup-password').value;
      const confirmPassword = document.getElementById('confirm-password').value;
      const role = document.getElementById('signup-role').value;
      const adminCode = document.getElementById('admin-code').value;

      if (password !== confirmPassword) {
        e.preventDefault();
        alert('Passwords do not match!');
        return;
      }

      if (role === 'admin' && adminCode.trim() === '') {
        e.preventDefault();
        alert('Please enter the admin secret code.');
        return;
      }
    });

    document.getElementById('forgot-password-btn').onclick = function() {
      const role = document.querySelector('select[name="role"]').value;
      const email = document.querySelector('input[name="email"]').value.trim();
      if (!role) {
          alert("Please select your role.");
          return;
      }
      if (!email) {
          alert("Please enter your registered email.");
          return;
      }
      window.location.href = 'forgot_password.php?email=' + 
          encodeURIComponent(email) + '&role=' + encodeURIComponent(role);
    };

   
document.addEventListener('DOMContentLoaded', function() {
    const roleSelect = document.querySelector('select[name="role"]');
    const backButton = document.querySelector('.back-link');
    
    if (backButton) {
        backButton.addEventListener('click', function(e) {
            if (roleSelect.value) {
                e.preventDefault();
                roleSelect.selectedIndex = 0; // Reset selection
            }
        });
    }
});

  </script>
</body>
</html>
