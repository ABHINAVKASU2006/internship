<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>QR Management System | Secure Device Tracking</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --primary: #38bdf8;        /* Light Blue */
      --secondary: #e0f2fe;      /* Very light blue */
      --accent: #fbbf24;         /* Soft yellow accent */
      --teal: #0ea5e9;           /* Deeper blue for contrast */
      --dark: #1e293b;           /* Dark blue-gray for text */
      --white: #ffffff;
      --light-gray: #f8fafc;
      --shadow: 0 4px 12px rgba(56, 189, 248, 0.10);
      --transition: all 0.3s ease;
    }
    
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: var(--light-gray);
      color: var(--dark);
      line-height: 1.6;
    }
    
    /* Navigation */
    .navbar {
      background: var(--white);
      padding: 1.2rem 5%;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: var(--shadow);
      position: sticky;
      top: 0;
      z-index: 1000;
    }
    
    .logo {
      font-size: 1.8rem;
      font-weight: 700;
      text-decoration: none;
      color: var(--primary);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    
    .logo i {
      font-size: 1.3em;
    }
    
    .nav-links {
      display: flex;
      gap: 2rem;
    }
    
    .nav-links a {
      color: var(--dark);
      text-decoration: none;
      font-weight: 500;
      padding: 0.5rem 0;
      position: relative;
      transition: var(--transition);
    }
    
    .nav-links a::after {
      content: '';
      position: absolute;
      bottom: 0;
      left: 0;
      width: 0;
      height: 2px;
      background: var(--primary);
      transition: var(--transition);
    }
    
    .nav-links a:hover::after,
    .nav-links a.active::after {
      width: 100%;
    }
    
    .nav-links a:hover,
    .nav-links a.active {
      color: var(--primary);
    }
    
    .auth-buttons {
      display: flex;
      gap: 1rem;
    }
    
    .btn {
      padding: 0.6rem 1.2rem;
      border-radius: 50px;
      font-weight: 600;
      cursor: pointer;
      transition: var(--transition);
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
    }
    
    .btn-outline {
      border: 2px solid var(--primary);
      color: var(--primary);
      background: transparent;
    }
    
    .btn-solid {
      background: var(--primary);
      color: var(--white);
      border: 2px solid var(--primary);
    }
    
    .btn-outline:hover {
      background: var(--primary);
      color: var(--white);
    }
    
    .btn-solid:hover {
      background: var(--teal);
      border-color: var(--teal);
    }
    
    .mobile-menu-btn {
      display: none;
      background: none;
      border: none;
      color: var(--primary);
      font-size: 1.5rem;
      cursor: pointer;
    }
    
    /* Hero Section */
    .hero {
      background: linear-gradient(135deg, rgba(56, 189, 248, 0.95) 0%, rgba(14, 165, 233, 0.95) 100%), 
                  url('https://images.unsplash.com/photo-1551288049-bebda4e38f71?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=2070&q=80');
      background-size: cover;
      background-position: center;
      color: var(--white);
      padding: 6rem 5%;
      text-align: center;
    }
    
    .hero-content {
      max-width: 800px;
      margin: 0 auto;
    }
    
    .hero h1 {
      font-size: 3rem;
      margin-bottom: 1.5rem;
      font-weight: 800;
      line-height: 1.2;
    }
    
    .hero p {
      font-size: 1.2rem;
      margin-bottom: 2.5rem;
      opacity: 0.9;
    }
    
    .cta-buttons {
      display: flex;
      justify-content: center;
      gap: 1.5rem;
      margin-top: 2rem;
      flex-wrap: wrap;
    }
    
    /* Features Section */
    .features {
      padding: 5rem 5%;
    }
    
    .section-title {
      text-align: center;
      margin-bottom: 3rem;
    }
    
    .section-title h2 {
      font-size: 2.2rem;
      color: var(--primary);
      margin-bottom: 1rem;
    }
    
    .section-title p {
      color: var(--dark);
      max-width: 700px;
      margin: 0 auto;
    }
    
    .features-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 2rem;
      margin-top: 3rem;
    }
    
    .feature-card {
      background: var(--white);
      padding: 2rem;
      border-radius: 0.5rem;
      box-shadow: var(--shadow);
      transition: var(--transition);
      text-align: center;
    }
    
    .feature-card:hover {
      transform: translateY(-10px);
    }
    
    .feature-icon {
      width: 80px;
      height: 80px;
      background: var(--accent);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 1.5rem;
      color: var(--primary);
      font-size: 2rem;
    }
    
    .feature-card h3 {
      color: var(--primary);
      margin-bottom: 1rem;
    }
    
    /* How It Works */
    .how-it-works {
      background: var(--white);
      padding: 5rem 5%;
      text-align: center;
    }
    
    .steps {
      display: flex;
      justify-content: center;
      gap: 2rem;
      margin-top: 3rem;
      flex-wrap: wrap;
    }
    
    .step {
      flex: 1;
      min-width: 250px;
      max-width: 300px;
      position: relative;
    }
    
    .step-number {
      width: 50px;
      height: 50px;
      background: var(--primary);
      color: var(--white);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.5rem;
      font-weight: 700;
      margin: 0 auto 1.5rem;
    }
    
    .step h3 {
      margin-bottom: 1rem;
      color: var(--primary);
    }
    
    .step::after {
      content: '';
      position: absolute;
      top: 25px;
      right: -30px;
      width: 30px;
      height: 2px;
      background: var(--teal);
    }
    
    .step:last-child::after {
      display: none;
    }
    
    /* Testimonials */
    .testimonials {
      padding: 5rem 5%;
      background: var(--accent);
    }
    
    .testimonial-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 2rem;
      margin-top: 3rem;
    }
    
    .testimonial-card {
      background: var(--white);
      padding: 2rem;
      border-radius: 0.5rem;
      box-shadow: var(--shadow);
    }
    
    .testimonial-text {
      font-style: italic;
      margin-bottom: 1.5rem;
      position: relative;
    }
    
    .testimonial-text::before {
      content: '"';
      font-size: 4rem;
      color: var(--teal);
      position: absolute;
      top: -20px;
      left: -15px;
      opacity: 0.3;
      font-family: serif;
    }
    
    .testimonial-author {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    
    .author-avatar {
      width: 50px;
      height: 50px;
      border-radius: 50%;
      background: var(--teal);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--white);
      font-weight: 700;
    }
    
    .author-info h4 {
      color: var(--primary);
    }
    
    .author-info p {
      font-size: 0.9rem;
      color: var(--dark);
      opacity: 0.8;
    }
    
    /* CTA Section */
    .cta-section {
      background: var(--primary);
      color: var(--white);
      padding: 4rem 5%;
      text-align: center;
    }
    
    .cta-section h2 {
      font-size: 2.2rem;
      margin-bottom: 1.5rem;
    }
    
    /* Footer */
    footer {
      background: var(--dark);
      color: var(--white);
      padding: 4rem 5% 2rem;
    }
    
    .footer-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 3rem;
      margin-bottom: 3rem;
    }
    
    .footer-logo {
      font-size: 1.8rem;
      font-weight: 700;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    
    .footer-logo i {
      font-size: 1.3em;
    }
    
    .footer-links h3 {
      margin-bottom: 1.5rem;
      font-size: 1.2rem;
    }
    
    .footer-links ul {
      list-style: none;
    }
    
    .footer-links li {
      margin-bottom: 0.8rem;
    }
    
    .footer-links a {
      color: var(--teal);
      text-decoration: none;
      transition: var(--transition);
    }
    
    .footer-links a:hover {
      color: var(--white);
      padding-left: 5px;
    }
    
    .social-links {
      display: flex;
      gap: 1.5rem;
      margin-top: 1.5rem;
    }
    
    .social-links a {
      color: var(--white);
      font-size: 1.2rem;
      transition: var(--transition);
    }
    
    .social-links a:hover {
      color: var(--teal);
      transform: translateY(-3px);
    }
    
    .copyright {
      text-align: center;
      padding-top: 2rem;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
      font-size: 0.9rem;
      color: var(--teal);
    }
    
    /* Responsive */
    @media (max-width: 992px) {
      .nav-links {
        gap: 1.5rem;
      }
      
      .hero h1 {
        font-size: 2.5rem;
      }
      
      .step::after {
        display: none;
      }
    }
    
    @media (max-width: 768px) {
      .mobile-menu-btn {
        display: block;
      }
      
      .nav-links {
        position: fixed;
        top: 80px;
        left: 0;
        width: 100%;
        background: var(--white);
        flex-direction: column;
        align-items: center;
        padding: 2rem 0;
        clip-path: circle(0px at 90% -10%);
        transition: all 0.5s ease-out;
        pointer-events: none;
        box-shadow: 0 10px 15px rgba(0, 0, 0, 0.1);
      }
      
      .nav-links.active {
        clip-path: circle(1000px at 90% -10%);
        pointer-events: all;
      }
      
      .auth-buttons {
        display: none;
      }
      
      .hero {
        padding: 4rem 5%;
      }
      
      .hero h1 {
        font-size: 2rem;
      }
      
      .hero p {
        font-size: 1rem;
      }
      
      .cta-buttons {
        flex-direction: column;
        gap: 1rem;
      }
      
      .btn {
        width: 100%;
        justify-content: center;
      }
    }
  </style>
</head>
<body>
  <!-- Navigation -->
  <nav class="navbar">
    <a href="#" class="logo">
      <i class="fas fa-qrcode"></i>
      QR Manager
    </a>
    
    <div class="nav-links" id="navLinks">
      <a href="#features" class="active">Home</a>
      <a href="#">Features</a>
      <a href="#">Solutions</a>
      <a href="#">Pricing</a>
      <a href="#">Contact</a>
    </div>
    
    <div class="auth-buttons">
      <a href="index3.php" class="btn btn-outline">Log In</a>
      <a href="index3.php" class="btn btn-solid">Get Started</a>
    </div>
    
    <button class="mobile-menu-btn" id="mobileMenuBtn">
      <i class="fas fa-bars"></i>
    </button>
  </nav>
  
  <!-- Hero Section -->
  <section class="hero">
    <div class="hero-content">
      <h1>Next-Gen QR Code Asset Tracking</h1>
      <p>Experience streamlined, secure, and intelligent management of your devices and digital assets with our all-in-one solution</p>
      
      <div class="cta-buttons">
        <a href="demo.html" class="btn btn-outline">
          <i class="fas fa-play-circle"></i> Watch Demo
        </a>
        <a href="register.html" class="btn btn-solid">
          <i class="fas fa-rocket"></i> Start Free Trial
        </a>
      </div>
    </div>
  </section>
  
  <!-- Features Section -->
  <section class="features">
    <div class="section-title">
      <h2>Powerful Features</h2>
      <p>Everything you need to efficiently manage your QR-enabled devices and digital assets</p>
    </div>
    
    <div class="features-grid">
      <div class="feature-card">
        <div class="feature-icon">
          <i class="fas fa-shield-alt"></i>
        </div>
        <h3>Secure Access Control</h3>
        <p>Role-based permissions ensure only authorized personnel can access and manage your QR systems.</p>
      </div>
      
      <div class="feature-card">
        <div class="feature-icon">
          <i class="fas fa-map-marker-alt"></i>
        </div>
        <h3>Real-time Tracking</h3>
        <p>Monitor your QR-enabled assets with live location tracking and status updates.</p>
      </div>
      
      <div class="feature-card">
        <div class="feature-icon">
          <i class="fas fa-chart-line"></i>
        </div>
        <h3>Advanced Analytics</h3>
        <p>Comprehensive dashboards provide insights into usage patterns and access history.</p>
      </div>
      
      <div class="feature-card">
        <div class="feature-icon">
          <i class="fas fa-users-cog"></i>
        </div>
        <h3>User Management</h3>
        <p>Easily manage team members with different permission levels and access rights.</p>
      </div>
      
      <div class="feature-card">
        <div class="feature-icon">
          <i class="fas fa-mobile-alt"></i>
        </div>
        <h3>Mobile Friendly</h3>
        <p>Full mobile compatibility allows management from anywhere, on any device.</p>
      </div>
      
      <div class="feature-card">
        <div class="feature-icon">
          <i class="fas fa-database"></i>
        </div>
        <h3>Secure Storage</h3>
        <p>Enterprise-grade security protects all your QR data with encryption and backups.</p>
      </div>
    </div>
  </section>
  
  <!-- How It Works -->
  <section class="how-it-works">
    <div class="section-title">
      <h2>How It Works</h2>
      <p>Simple steps to transform your asset management with QR technology</p>
    </div>
    
    <div class="steps">
      <div class="step">
        <div class="step-number">1</div>
        <h3>Generate QR Codes</h3>
        <p>Create unique QR codes for each of your devices or assets with our easy-to-use generator.</p>
      </div>
      
      <div class="step">
        <div class="step-number">2</div>
        <h3>Assign & Deploy</h3>
        <p>Assign QR codes to specific assets, locations, or personnel and deploy them in your ecosystem.</p>
      </div>
      
      <div class="step">
        <div class="step-number">3</div>
        <h3>Manage & Track</h3>
        <p>Monitor usage, track locations, and manage access through our intuitive dashboard.</p>
      </div>
    </div>
  </section>
  
  <!-- Testimonials -->
  <section class="testimonials">
    <div class="section-title">
      <h2>Trusted by Industry Leaders</h2>
      <p>What our customers say about our QR management system</p>
    </div>
    
    <div class="testimonial-grid">
      <div class="testimonial-card">
        <div class="testimonial-text">
          The QR Management System transformed how we track our equipment. Implementation was seamless and the results were immediate.
        </div>
        <div class="testimonial-author">
          <div class="author-avatar">JD</div>
          <div class="author-info">
            <h4>John Dawson</h4>
            <p>CTO, TechCorp</p>
          </div>
        </div>
      </div>
      
      <div class="testimonial-card">
        <div class="testimonial-text">
          We've reduced asset loss by 75% since implementing this system. The real-time tracking is invaluable for our operations.
        </div>
        <div class="testimonial-author">
          <div class="author-avatar">SM</div>
          <div class="author-info">
            <h4>Sarah Miller</h4>
            <p>Operations Director, LogiChain</p>
          </div>
        </div>
      </div>
      
      <div class="testimonial-card">
        <div class="testimonial-text">
          The security features give us peace of mind knowing our sensitive equipment is properly tracked and managed.
        </div>
        <div class="testimonial-author">
          <div class="author-avatar">RK</div>
          <div class="author-info">
            <h4>Robert Kim</h4>
            <p>Security Manager, SafeSystems</p>
          </div>
        </div>
      </div>
    </div>
  </section>
  
  <!-- CTA Section -->
  <section class="cta-section">
    <h2>Ready to Transform Your Asset Management?</h2>
    <p>Join thousands of businesses using our QR Management System</p>
    <div class="cta-buttons" style="margin-top: 2rem;">
      <a href="pricing.html" class="btn btn-outline">View Plans</a>
      <a href="register.html" class="btn btn-solid">Start Free Trial</a>
    </div>
  </section>
  
  <!-- Footer -->
  <footer>
    <div class="footer-grid">
      <div class="footer-col">
        <div class="footer-logo">
          <i class="fas fa-qrcode"></i>
          QR Manager
        </div>
        <p>Modern, secure QR management solutions for businesses of all sizes.</p>
        <div class="social-links">
          <a href="#"><i class="fab fa-facebook-f"></i></a>
          <a href="#"><i class="fab fa-twitter"></i></a>
          <a href="#"><i class="fab fa-linkedin-in"></i></a>
          <a href="#"><i class="fab fa-instagram"></i></a>
        </div>
      </div>
      
      <div class="footer-links">
        <h3>Product</h3>
        <ul>
          <li><a href="#">Features</a></li>
          <li><a href="#">Solutions</a></li>
          <li><a href="#">Pricing</a></li>
          <li><a href="#">Integrations</a></li>
        </ul>
      </div>
      
      <div class="footer-links">
        <h3>Resources</h3>
        <ul>
          <li><a href="#">Documentation</a></li>
          <li><a href="#">API Reference</a></li>
          <li><a href="#">Guides</a></li>
          <li><a href="#">Blog</a></li>
        </ul>
      </div>
      
      <div class="footer-links">
        <h3>Company</h3>
        <ul>
          <li><a href="#">About Us</a></li>
          <li><a href="#">Careers</a></li>
          <li><a href="#">Contact</a></li>
          <li><a href="#">Legal</a></li>
        </ul>
      </div>
    </div>
    
    <div class="copyright">
      &copy; 2023 QR Management System. All rights reserved.
    </div>
  </footer>
  
  <script>
    // Mobile Menu Toggle
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const navLinks = document.getElementById('navLinks');
    
    mobileMenuBtn.addEventListener('click', () => {
      navLinks.classList.toggle('active');
      mobileMenuBtn.innerHTML = navLinks.classList.contains('active') 
        ? '<i class="fas fa-times"></i>' 
        : '<i class="fas fa-bars"></i>';
    });
    
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', function(e) {
        e.preventDefault();
        
        if (this.getAttribute('href') === '#') return;
        
        document.querySelector(this.getAttribute('href')).scrollIntoView({
          behavior: 'smooth'
        });
        
        // Close mobile menu if open
        if (navLinks.classList.contains('active')) {
          navLinks.classList.remove('active');
          mobileMenuBtn.innerHTML = '<i class="fas fa-bars"></i>';
        }
      });
    });
    
    // Add shadow to navbar on scroll
    window.addEventListener('scroll', () => {
      if (window.scrollY > 10) {
        document.querySelector('.navbar').style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.1)';
      } else {
        document.querySelector('.navbar').style.boxShadow = '0 4px 12px rgba(61, 141, 122, 0.1)';
      }
    });
  </script>
</body>
</html>