const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;

// Helper to resolve base URL dynamically using req.get('host')
const getBaseUrl = (req) => {
  const protocol = req.protocol;
  const host = req.get('host');
  return `${protocol}://${host}`;
};

// Generate or load JWT Secret Key using crypto module & save to secret.key
const secretKeyPath = path.join(__dirname, 'secret.key');
let JWT_SECRET;

if (fs.existsSync(secretKeyPath)) {
  JWT_SECRET = fs.readFileSync(secretKeyPath, 'utf8').trim();
  console.log('Loaded existing JWT secret from secret.key');
} else {
  JWT_SECRET = crypto.randomBytes(64).toString('hex');
  fs.writeFileSync(secretKeyPath, JWT_SECRET, 'utf8');
  console.log('Generated new JWT secret and saved to secret.key');
}

// In-Memory Storage Databases
const users = []; // { id, email, password }
const oauthApps = []; // { clientId, clientSecret, name, redirectUris }
const deviceCodes = new Map(); // device_code -> { userCode, clientId, scope, status, userId, createdAt, expiresAt }
const authCodes = new Map(); // code -> { userId, clientId, redirectUri, codeChallenge }
const apiTokens = []; // { id, name, token, userId }
const issuedTokens = []; // { id, access_token, id_token, token_type, expires_in, scope, client_id, user_id, grant_type, issued_at, expires_at }
const activeSessions = new Set();
const verificationStore = new Map(); // Store active 6-digit verification codes: email -> { code, expiresAt, password, apiKey, senderEmail }

// Middleware to authenticate Bearer JWT with 401 handling for invalid/expired tokens
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized: No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
    req.user = user;
    next();
  });
}

// ==========================================
// REGISTRATION, LOGIN & LOGOUT HTML UI & ENDPOINTS
// ==========================================

// Render Register Page
app.get('/register', (req, res) => {
  const htmlContent = `<!DOCTYPE html>
  <html>
    <head>
      <title>User Registration</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 40px; background: #f4f7f6; }
        .container { max-width: 500px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h2 { margin-top: 0; color: #333; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #555; }
        input { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 5px; }
        button:hover { background: #0056b3; }
        .btn-verify { background: #28a745; display: none; }
        .btn-verify:hover { background: #218838; }
        .message { margin-top: 15px; padding: 10px; border-radius: 4px; display: none; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        #verifySection { display: none; margin-top: 25px; border-top: 1px solid #eee; padding-top: 20px; }
        .links { margin-top: 15px; text-align: center; font-size: 14px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Create an Account</h2>
        <form id="registerForm">
          <div class="form-group">
            <label>Email:</label>
            <input type="email" id="email" placeholder="user@example.com" required />
          </div>
          <div class="form-group">
            <label>New Password:</label>
            <input type="password" id="password" placeholder="••••••••" required />
          </div>
          <div class="form-group">
            <label>Confirm Password:</label>
            <input type="password" id="confirmPassword" placeholder="••••••••" required />
          </div>
          <div class="form-group">
            <label>Brevo API Key:</label>
            <input type="password" id="apiKey" placeholder="xkeysib-..." required />
          </div>
          <div class="form-group">
            <label>Brevo Sender Email:</label>
            <input type="email" id="senderEmail" placeholder="sender@yourdomain.com" required />
          </div>
          <button type="submit" id="submitBtn">Send Verification Code</button>
        </form>

        <div id="verifySection">
          <h3>Enter Verification Code</h3>
          <form id="verifyForm">
            <div class="form-group">
              <label>6-Digit Code sent to Email:</label>
              <input type="text" id="verificationCode" placeholder="123456" maxlength="6" pattern="[0-9]{6}" required />
            </div>
            <button type="submit" class="btn-verify" style="display: block;">Complete Registration</button>
          </form>
        </div>

        <div id="statusMessage" class="message"></div>
        <div class="links">
          Already have an account? <a href="/login">Log in here</a> | <a href="/">Dashboard</a>
        </div>
      </div>

      <script>
        const statusDiv = document.getElementById('statusMessage');
        let registeredEmail = '';

        function showMessage(msg, isError = false) {
          statusDiv.style.display = 'block';
          statusDiv.className = 'message ' + (isError ? 'error' : 'success');
          statusDiv.textContent = msg;
        }

        document.getElementById('registerForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const password = document.getElementById('password').value;
          const confirmPassword = document.getElementById('confirmPassword').value;

          if (password !== confirmPassword) {
            showMessage('Passwords do not match.', true);
            return;
          }

          showMessage('Sending verification code via Brevo...', false);

          const payload = {
            email: document.getElementById('email').value,
            password: password,
            apiKey: document.getElementById('apiKey').value,
            senderEmail: document.getElementById('senderEmail').value
          };

          try {
            const response = await fetch('/api/auth/send-register-code', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (response.ok) {
              registeredEmail = payload.email;
              document.getElementById('verifySection').style.display = 'block';
              document.getElementById('registerForm').style.display = 'none';
              showMessage('Success: ' + data.message);
            } else {
              showMessage('Error: ' + (data.error || 'Failed to send verification code'), true);
            }
          } catch (err) {
            showMessage('Network error: ' + err.message, true);
          }
        });

        document.getElementById('verifyForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          showMessage('Verifying code and creating account...', false);

          const payload = {
            email: registeredEmail,
            code: document.getElementById('verificationCode').value
          };

          try {
            const response = await fetch('/api/auth/verify-register', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (response.ok) {
              showMessage('Account registered successfully! Redirecting to login...');
              setTimeout(() => { window.location.href = '/login'; }, 2000);
            } else {
              showMessage('Error: ' + (data.error || 'Verification failed'), true);
            }
          } catch (err) {
            showMessage('Network error: ' + err.message, true);
          }
        });
      </script>
    </body>
  </html>`;
  res.send(htmlContent);
});

// Render Login Page
app.get('/login', (req, res) => {
  const htmlContent = `<!DOCTYPE html>
  <html>
    <head>
      <title>User Login</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 40px; background: #f4f7f6; }
        .container { max-width: 400px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h2 { margin-top: 0; color: #333; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #555; }
        input { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 5px; }
        button:hover { background: #218838; }
        .message { margin-top: 15px; padding: 10px; border-radius: 4px; display: none; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .links { margin-top: 15px; text-align: center; font-size: 14px; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>User Login</h2>
        <form id="loginForm">
          <div class="form-group">
            <label>Email:</label>
            <input type="email" id="email" placeholder="user@example.com" required />
          </div>
          <div class="form-group">
            <label>Password:</label>
            <input type="password" id="password" placeholder="••••••••" required />
          </div>
          <button type="submit">Log In</button>
        </form>

        <div id="statusMessage" class="message"></div>
        <pre id="tokenResult" style="display:none;"></pre>
        <div class="links">
          Don't have an account? <a href="/register">Register here</a> | <a href="/reset">Reset Password</a> | <a href="/">Dashboard</a>
        </div>
      </div>

      <script>
        const statusDiv = document.getElementById('statusMessage');

        function showMessage(msg, isError = false) {
          statusDiv.style.display = 'block';
          statusDiv.className = 'message ' + (isError ? 'error' : 'success');
          statusDiv.textContent = msg;
        }

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          showMessage('Logging in...', false);

          const payload = {
            email: document.getElementById('email').value,
            password: document.getElementById('password').value
          };

          try {
            const response = await fetch('/api/auth/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (response.ok) {
              showMessage('Login successful! Token saved to local storage.');
              localStorage.setItem('access_token', data.access_token);
              const tokenBox = document.getElementById('tokenResult');
              tokenBox.style.display = 'block';
              tokenBox.textContent = 'Access Token:\\n' + data.access_token;
            } else {
              showMessage('Error: ' + (data.error || 'Invalid credentials'), true);
            }
          } catch (err) {
            showMessage('Network error: ' + err.message, true);
          }
        });
      </script>
    </body>
  </html>`;
  res.send(htmlContent);
});

// Render Logout Page
app.get('/logout', (req, res) => {
  const htmlContent = `<!DOCTYPE html>
  <html>
    <head>
      <title>User Logout</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 40px; background: #f4f7f6; }
        .container { max-width: 400px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
        h2 { margin-top: 0; color: #333; }
        button { width: 100%; padding: 12px; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 15px; }
        button:hover { background: #c82333; }
        .message { margin-top: 15px; padding: 10px; border-radius: 4px; display: none; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .links { margin-top: 20px; font-size: 14px; }
        #authStatus { font-weight: bold; margin-bottom: 15px; color: #555; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Session Management</h2>
        <div id="authStatus">Checking status...</div>
        <button id="logoutBtn" style="display:none;">Log Out Now</button>

        <div id="statusMessage" class="message"></div>
        <div class="links">
          <a href="/login">Log In</a> | <a href="/">Dashboard</a>
        </div>
      </div>

      <script>
        const statusDiv = document.getElementById('statusMessage');
        const authStatusDiv = document.getElementById('authStatus');
        const logoutBtn = document.getElementById('logoutBtn');
        const token = localStorage.getItem('access_token');

        if (token) {
          authStatusDiv.textContent = 'Status: Logged In';
          authStatusDiv.style.color = '#28a745';
          logoutBtn.style.display = 'block';
        } else {
          authStatusDiv.textContent = 'Status: Not Logged In';
          authStatusDiv.style.color = '#dc3545';
        }

        function showMessage(msg, isError = false) {
          statusDiv.style.display = 'block';
          statusDiv.className = 'message ' + (isError ? 'error' : 'success');
          statusDiv.textContent = msg;
        }

        logoutBtn.addEventListener('click', async () => {
          showMessage('Logging out...', false);
          try {
            const response = await fetch('/api/auth/logout', {
              method: 'POST',
              headers: { 
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
              }
            });
            const data = await response.json();
            localStorage.removeItem('access_token');
            authStatusDiv.textContent = 'Status: Not Logged In';
            authStatusDiv.style.color = '#dc3545';
            logoutBtn.style.display = 'none';
            showMessage('Successfully logged out!');
          } catch (err) {
            showMessage('Error logging out: ' + err.message, true);
          }
        });
      </script>
    </body>
  </html>`;
  res.send(htmlContent);
});

// Render Reset Password Page
app.get('/reset', (req, res) => {
  const htmlContent = `<!DOCTYPE html>
  <html>
    <head>
      <title>Reset Password</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 40px; background: #f4f7f6; }
        .container { max-width: 400px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h2 { margin-top: 0; color: #333; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #555; }
        input { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; padding: 12px; background: #ffc107; color: #333; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 5px; font-weight: bold; }
        button:hover { background: #e0a800; }
        .message { margin-top: 15px; padding: 10px; border-radius: 4px; display: none; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .links { margin-top: 15px; text-align: center; font-size: 14px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Reset Password</h2>
        <form id="resetForm">
          <div class="form-group">
            <label>Email:</label>
            <input type="email" id="email" placeholder="user@example.com" required />
          </div>
          <div class="form-group">
            <label>New Password:</label>
            <input type="password" id="password" placeholder="••••••••" required />
          </div>
          <div class="form-group">
            <label>Confirm New Password:</label>
            <input type="password" id="confirmPassword" placeholder="••••••••" required />
          </div>
          <button type="submit">Reset Password</button>
        </form>

        <div id="statusMessage" class="message"></div>
        <div class="links">
          Remembered your password? <a href="/login">Log in here</a> | <a href="/">Dashboard</a>
        </div>
      </div>

      <script>
        const statusDiv = document.getElementById('statusMessage');

        function showMessage(msg, isError = false) {
          statusDiv.style.display = 'block';
          statusDiv.className = 'message ' + (isError ? 'error' : 'success');
          statusDiv.textContent = msg;
        }

        document.getElementById('resetForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const password = document.getElementById('password').value;
          const confirmPassword = document.getElementById('confirmPassword').value;

          if (password !== confirmPassword) {
            showMessage('Passwords do not match.', true);
            return;
          }

          showMessage('Updating password...', false);

          const payload = {
            email: document.getElementById('email').value,
            password: password
          };

          try {
            const response = await fetch('/api/auth/reset', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (response.ok) {
              showMessage('Password reset successfully! Redirecting to login...');
              setTimeout(() => { window.location.href = '/login'; }, 2000);
            } else {
              showMessage('Error: ' + (data.error || 'Failed to reset password'), true);
            }
          } catch (err) {
            showMessage('Network error: ' + err.message, true);
          }
        });
      </script>
    </body>
  </html>`;
  res.send(htmlContent);
});

// Step 1 of Registration: Send 6-digit verification code via Brevo API
app.post('/api/auth/send-register-code', async (req, res) => {
  const { email, password, apiKey, senderEmail } = req.body;

  if (!email || !password || !apiKey || !senderEmail) {
    return res.status(400).json({ error: 'All fields (email, password, apiKey, senderEmail) are required' });
  }

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'User already exists with this email' });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

  verificationStore.set(email.toLowerCase(), { code, expiresAt, password, apiKey, senderEmail });

  try {
    const brevoPayload = {
      sender: { email: senderEmail },
      to: [{ email: email }],
      subject: 'Your Account Verification Code',
      htmlContent: `<div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>Account Verification</h2>
        <p>Your 6-digit registration verification code is:</p>
        <h1 style="color: #007bff; letter-spacing: 4px;">${code}</h1>
        <p>This code is valid for 10 minutes.</p>
      </div>`
    };

    await axios.post('https://api.brevo.com/v3/smtp/email', brevoPayload, {
      headers: {
        'accept': 'application/json',
        'api-key': apiKey,
        'content-type': 'application/json'
      }
    });

    res.json({ message: 'Verification code sent successfully to your email' });
  } catch (error) {
    const errorDetails = error.response ? error.response.data : error.message;
    res.status(500).json({ error: 'Failed to send email via Brevo API', details: errorDetails });
  }
});

// Step 2 of Registration: Verify code and create user
app.post('/api/auth/verify-register', (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: 'Email and verification code are required' });
  }

  const record = verificationStore.get(email.toLowerCase());

  if (!record) {
    return res.status(400).json({ error: 'No active registration found for this email' });
  }

  if (Date.now() > record.expiresAt) {
    verificationStore.delete(email.toLowerCase());
    return res.status(400).json({ error: 'Verification code has expired. Please register again.' });
  }

  if (record.code !== code.trim()) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  // Create User
  const newUser = { id: crypto.randomUUID(), email: email.toLowerCase(), password: record.password };
  users.push(newUser);

  verificationStore.delete(email.toLowerCase());
  res.status(201).json({ message: 'Account registered successfully', userId: newUser.id });
});

// ==========================================
// BREVO EMAIL VERIFICATION UI & API ENDPOINTS
// ==========================================

// Render Brevo Verification Form UI
app.get('/verify-email', (req, res) => {
  const htmlContent = `<!DOCTYPE html>
  <html>
    <head>
      <title>Brevo Email Verification</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 40px; background: #f4f7f6; }
        .container { max-width: 500px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h2 { margin-top: 0; color: #333; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #555; }
        input { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 5px; }
        button:hover { background: #0056b3; }
        .btn-verify { background: #28a745; }
        .btn-verify:hover { background: #218838; }
        .message { margin-top: 15px; padding: 10px; border-radius: 4px; display: none; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        hr { margin: 25px 0; border: 0; border-top: 1px solid #eee; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Send Verification Code</h2>
        <form id="sendCodeForm">
          <div class="form-group">
            <label>Brevo API Key:</label>
            <input type="password" id="apiKey" placeholder="xkeysib-..." required />
          </div>
          <div class="form-group">
            <label>Sender Email:</label>
            <input type="email" id="senderEmail" placeholder="sender@yourdomain.com" required />
          </div>
          <div class="form-group">
            <label>Recipient Email:</label>
            <input type="email" id="recipientEmail" placeholder="recipient@example.com" required />
          </div>
          <button type="submit">Send 6-Digit Code</button>
        </form>

        <hr/>

        <h2>Verify Code</h2>
        <form id="verifyCodeForm">
          <div class="form-group">
            <label>Recipient Email:</label>
            <input type="email" id="verifyEmail" placeholder="recipient@example.com" required />
          </div>
          <div class="form-group">
            <label>6-Digit Verification Code:</label>
            <input type="text" id="verificationCode" placeholder="123456" maxlength="6" pattern="[0-9]{6}" required />
          </div>
          <button type="submit" class="btn-verify">Verify Code</button>
        </form>

        <div id="statusMessage" class="message"></div>
      </div>

      <script>
        const statusDiv = document.getElementById('statusMessage');

        function showMessage(msg, isError = false) {
          statusDiv.style.display = 'block';
          statusDiv.className = 'message ' + (isError ? 'error' : 'success');
          statusDiv.textContent = msg;
        }

        document.getElementById('sendCodeForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          showMessage('Sending code via Brevo API...', false);

          const payload = {
            apiKey: document.getElementById('apiKey').value,
            senderEmail: document.getElementById('senderEmail').value,
            recipientEmail: document.getElementById('recipientEmail').value
          };

          try {
            const response = await fetch('/api/brevo/send-code', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (response.ok) {
              document.getElementById('verifyEmail').value = payload.recipientEmail;
              showMessage('Success: ' + data.message);
            } else {
              showMessage('Error: ' + (data.error || 'Failed to send code'), true);
            }
          } catch (err) {
            showMessage('Network error: ' + err.message, true);
          }
        });

        document.getElementById('verifyCodeForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          showMessage('Verifying code...', false);

          const payload = {
            email: document.getElementById('verifyEmail').value,
            code: document.getElementById('verificationCode').value
          };

          try {
            const response = await fetch('/api/brevo/verify-code', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (response.ok) {
              showMessage('Success: ' + data.message);
            } else {
              showMessage('Error: ' + (data.error || 'Verification failed'), true);
            }
          } catch (err) {
            showMessage('Network error: ' + err.message, true);
          }
        });
      </script>
    </body>
  </html>`;
  res.send(htmlContent);
});

// Endpoint to send 6-digit code via Brevo REST API using Axios
app.post('/api/brevo/send-code', async (req, res) => {
  const { apiKey, senderEmail, recipientEmail } = req.body;

  if (!apiKey || !senderEmail || !recipientEmail) {
    return res.status(400).json({ error: 'Brevo API Key, Sender Email, and Recipient Email are required' });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 10 * 60 * 1000;

  verificationStore.set(recipientEmail.toLowerCase(), { code, expiresAt });

  try {
    const brevoPayload = {
      sender: { email: senderEmail },
      to: [{ email: recipientEmail }],
      subject: 'Your Verification Code',
      htmlContent: `<div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>Email Verification</h2>
        <p>Your 6-digit verification code is:</p>
        <h1 style="color: #007bff; letter-spacing: 4px;">${code}</h1>
        <p>This code is valid for 10 minutes.</p>
      </div>`
    };

    const response = await axios.post('https://api.brevo.com/v3/smtp/email', brevoPayload, {
      headers: {
        'accept': 'application/json',
        'api-key': apiKey,
        'content-type': 'application/json'
      }
    });

    res.json({ message: 'Verification code sent successfully', messageId: response.data.messageId });
  } catch (error) {
    const errorDetails = error.response ? error.response.data : error.message;
    res.status(500).json({ error: 'Failed to send email via Brevo API', details: errorDetails });
  }
});

app.post('/api/brevo/verify-code', (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: 'Email and verification code are required' });
  }

  const record = verificationStore.get(email.toLowerCase());

  if (!record) {
    return res.status(400).json({ error: 'No verification code was requested for this email' });
  }

  if (Date.now() > record.expiresAt) {
    verificationStore.delete(email.toLowerCase());
    return res.status(400).json({ error: 'Verification code has expired. Please request a new one.' });
  }

  if (record.code !== code.trim()) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  verificationStore.delete(email.toLowerCase());
  res.json({ message: 'Email verified successfully!' });
});

// ==========================================
// ROOT DASHBOARD & DOCUMENTATION ENDPOINTS
// ==========================================
app.get('/', (req, res) => {
  const baseUrl = getBaseUrl(req);
  const htmlContent = `<html>
    <head><title>OAuth 2.0 / OIDC Dashboard</title></head>
    <body style="font-family: Arial, sans-serif; padding: 40px; background: #f9f9f9;">
      <div style="max-width: 650px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <h2>OAuth 2.0 / OIDC Authorization Server</h2>
        <p>
          <a href="${baseUrl}/docs" target="_blank">API Documentation</a> | 
          <a href="${baseUrl}/register" target="_blank">Register</a> | 
          <a href="${baseUrl}/login" target="_blank">Login</a> | 
          <a href="${baseUrl}/logout" target="_blank">Logout</a> | 
          <a href="${baseUrl}/reset" target="_blank">Reset Password</a> | 
          <a href="${baseUrl}/oauth-apps" target="_blank">Manage OAuth Apps</a> | 
          <a href="${baseUrl}/verify-email" target="_blank">Brevo Email Verification</a>
        </p>
        <p>Discovery configuration: <a href="${baseUrl}/.well-known/openid-configuration" target="_blank">${baseUrl}/.well-known/openid-configuration</a></p>
        <hr style="margin: 20px 0;"/>
        <h3>Fetch System RAM</h3>
        <p>Enter your Access Token below to query system RAM status (or use the button to fetch automatically if logged in):</p>
        <div style="margin-bottom: 10px;">
          <input type="text" id="accessToken" placeholder="Paste access token here" style="width: 100%; padding: 10px; box-sizing: border-box;" />
        </div>
        <button onclick="fetchRam()" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">Fetch RAM</button>
        <pre id="ramResult" style="background: #f4f4f4; padding: 15px; margin-top: 20px; border-radius: 4px; overflow-x: auto;"></pre>
      </div>
      <script>
        // Auto-populate token if stored in localStorage from login
        window.onload = () => {
          const savedToken = localStorage.getItem('access_token');
          if (savedToken) {
            document.getElementById('accessToken').value = savedToken;
          }
        };

        async function fetchRam() {
          const token = document.getElementById('accessToken').value;
          if (!token) {
            document.getElementById('ramResult').textContent = 'Error: Please provide an access token.';
            return;
          }
          try {
            const res = await fetch('/api/get-ram', { headers: { 'Authorization': 'Bearer ' + token } });
            const data = await res.json();
            document.getElementById('ramResult').textContent = JSON.stringify(data, null, 2);
          } catch (err) {
            document.getElementById('ramResult').textContent = 'Error fetching RAM: ' + err.message;
          }
        }
      </script>
    </body>
  </html>`;
  res.send(htmlContent);
});

app.get('/docs', (req, res) => {
  res.send(`<html>
    <head><title>API Documentation</title></head>
    <body style="font-family: Arial, sans-serif; padding: 40px; max-width: 800px; margin: auto;">
      <h1>API Documentation</h1>
      <ul>
        <li><strong>GET /register</strong> - User Registration Page with Brevo Verification</li>
        <li><strong>GET /login</strong> - User Login Page</li>
        <li><strong>GET /logout</strong> - Session Logout Page</li>
        <li><strong>GET /reset</strong> - Reset Password Page</li>
        <li><strong>GET /verify-email</strong> - Brevo Verification UI Form</li>
        <li><strong>POST /api/brevo/send-code</strong> - Send 6-digit code via Brevo API</li>
        <li><strong>POST /api/brevo/verify-code</strong> - Verify 6-digit code</li>
        <li><strong>GET /api/healthz</strong> - System health check</li>
        <li><strong>GET /api/test/sleep?ms=1000</strong> - Delays response for specified milliseconds</li>
        <li><strong>GET /api/oauth/status</strong> - OAuth subsystem status</li>
        <li><strong>GET /api/auth/status</strong> - Auth subsystem status</li>
        <li><strong>GET /api/get-ram</strong> - Returns system RAM info (requires auth)</li>
        <li><strong>POST /api/auth/register</strong> - Register a new user</li>
        <li><strong>POST /api/auth/login</strong> - Authenticate user & get access token</li>
        <li><strong>POST /api/auth/reset</strong> - Reset user password</li>
        <li><strong>POST /api/auth/switch</strong> - Switch active account context</li>
        <li><strong>GET /api/auth/whoami & /api/whoami</strong> - Get token identity details</li>
        <li><strong>GET /oauth/userinfo</strong> - OpenID Connect UserInfo endpoint</li>
        <li><strong>POST /oauth/device/authorize</strong> - Device Code Grant authorization request</li>
        <li><strong>POST /oauth/device/code</strong> - Generate device code (RFC 8628)</li>
        <li><strong>GET /oauth/device/code</strong> - List all device codes</li>
        <li><strong>DELETE /oauth/device/code</strong> - Delete a device code</li>
        <li><strong>POST /oauth/token</strong> - OAuth token exchange endpoint</li>
        <li><strong>GET /oauth/token</strong> - List all issued access tokens</li>
        <li><strong>DELETE /oauth/token</strong> - Revoke an access token</li>
        <li><strong>GET /.well-known/oauth-authorization-server</strong> - OAuth 2.0 Server Metadata</li>
        <li><strong>GET /.well-known/openid-configuration</strong> - OpenID Connect Configuration</li>
        <li><strong>GET /oauth-apps</strong> - HTML View for Registered OAuth Applications</li>
      </ul>
    </body>
  </html>`);
});

// ==========================================
// SYSTEM & HEALTH ENDPOINTS
// ==========================================
app.get('/api/healthz', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('/api/test/sleep', async (req, res) => {
  const ms = parseInt(req.query.ms, 10) || 1000;
  await new Promise(resolve => setTimeout(resolve, ms));
  res.json({ status: 'ok', slept_ms: ms });
});

app.get('/api/get-ram', authenticateToken, (req, res) => {
  res.json({ ram_mb: 1024 });
});

app.get('/api/oauth/status', (req, res) => {
  res.json({
    status: 'active',
    server: 'OAuth 2.0 / OIDC Provider Running',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/auth/status', authenticateToken, (req, res) => {
  res.json({
    status: 'authenticated',
    user_id: req.user.sub,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/whoami', authenticateToken, (req, res) => {
  res.json({ user_id: req.user.sub, email: req.user.email || null, token_details: req.user });
});

app.get('/api/auth/whoami', authenticateToken, (req, res) => {
  res.json({ user_id: req.user.sub, email: req.user.email || null });
});

app.post('/api/auth/switch', authenticateToken, (req, res) => {
  const { target_user_id } = req.body;
  const targetUser = users.find(u => u.id === target_user_id);
  if (!targetUser) return res.status(404).json({ error: 'Target user not found' });

  const newAccessToken = jwt.sign({ sub: targetUser.id, email: targetUser.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ message: 'Account context switched successfully', access_token: newAccessToken });
});

app.get('/api/account/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, email: user.email, profile: { role: 'Standard', status: 'active' } });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, email: user.email });
});

// ==========================================
// OIDC USERINFO ENDPOINT
// ==========================================
app.get('/oauth/userinfo', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    sub: user.id,
    email: user.email,
    email_verified: true,
    organizations: [{ id: 'org_1', name: 'Default Organization' }]
  });
});

// ==========================================
// OAUTH 2.0 & OIDC DISCOVERY ENDPOINTS
// ==========================================
const getOAuthConfig = (baseUrl) => ({
  issuer: baseUrl,
  authorization_endpoint: `${baseUrl}/api/oauth/authorize`,
  token_endpoint: `${baseUrl}/oauth/token`,
  userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
  device_authorization_endpoint: `${baseUrl}/oauth/device/authorize`,
  jwks_uri: `${baseUrl}/.well-known/jwks.json`,
  response_types_supported: ['code', 'token'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['HS256'],
  scopes_supported: ['openid', 'profile', 'email', 'offline_access', 'api.connectors.read', 'api.connectors.invoke'],
  token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
  grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code']
});

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json(getOAuthConfig(getBaseUrl(req)));
});

app.get('/.well-known/openid-configuration', (req, res) => {
  res.json(getOAuthConfig(getBaseUrl(req)));
});

app.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: [] });
});

// ==========================================
// USER AUTHENTICATION & MANAGEMENT
// ==========================================
app.post('/api/auth/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'User already exists' });
  }
  const newUser = { id: crypto.randomUUID(), email, password };
  users.push(newUser);
  res.status(201).json({ message: 'Account registered successfully', userId: newUser.id });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const accessToken = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  activeSessions.add(accessToken);
  res.json({ message: 'Login successful', access_token: accessToken });
});

app.post('/api/auth/reset', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.password = password;
  res.json({ message: 'Password reset successfully' });
});

app.get('/api/auth/scope', authenticateToken, (req, res) => {
  res.json({
    scopes: ['openid', 'profile', 'email', 'offline_access', 'api.connectors.read', 'api.connectors.invoke']
  });
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token) activeSessions.delete(token);
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/v4/user', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    id: user.id,
    email: user.email,
    organizations: [{ id: 'org_1', name: 'Default Organization' }]
  });
});

app.get('/api/auth/list', (req, res) => {
  res.json(users.map(({ id, email }) => ({ id, email })));
});

// ==========================================
// OAUTH CLIENT APPLICATIONS MANAGEMENT & UI
// ==========================================
app.post('/api/oauth/apps', (req, res) => {
  const { name, redirectUris } = req.body;
  const clientId = 'client_' + crypto.randomBytes(8).toString('hex');
  const clientSecret = 'secret_' + crypto.randomBytes(16).toString('hex');

  const appEntry = { clientId, clientSecret, name, redirectUris: redirectUris || [] };
  oauthApps.push(appEntry);
  res.status(201).json(appEntry);
});

app.get('/api/oauth/apps', (req, res) => {
  res.json(oauthApps.map(({ clientId, clientSecret, name, redirectUris }) => ({ clientId, clientSecret, name, redirectUris })));
});

app.get('/api/oauth/apps/:id', (req, res) => {
  const appEntry = oauthApps.find(a => a.clientId === req.params.id);
  if (!appEntry) return res.status(404).json({ error: 'App not found' });
  res.json(appEntry);
});

app.delete('/api/oauth/apps/:id', (req, res) => {
  const index = oauthApps.findIndex(a => a.clientId === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'App not found' });
  oauthApps.splice(index, 1);
  res.json({ message: 'OAuth application deleted successfully' });
});

app.get('/oauth-apps', (req, res) => {
  const htmlContent = `<html>
    <head><title>Registered OAuth Apps</title></head>
    <body style="font-family: Arial, sans-serif; padding: 40px; background: #f9f9f9;">
      <div style="max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <h2>Registered OAuth Applications</h2>
        <p><a href="/">Back to Dashboard</a></p>
        <hr style="margin: 20px 0;"/>
        <table border="1" cellpadding="10" cellspacing="0" style="width: 100%; border-collapse: collapse;">
          <thead>
            <tr style="background: #f1f1f1;">
              <th>App Name</th><th>Client ID</th><th>Client Secret</th><th>Redirect URIs</th>
            </tr>
          </thead>
          <tbody>
            ${oauthApps.length === 0 ? '<tr><td colspan="4" style="text-align: center;">No apps registered yet.</td></tr>' : oauthApps.map(app => `
              <tr>
                <td>${app.name}</td>
                <td>${app.clientId}</td>
                <td>${app.clientSecret}</td>
                <td>${app.redirectUris.join(', ')}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </body>
  </html>`;
  res.send(htmlContent);
});

// ==========================================
// AUTHORIZATION CODE & DEVICE GRANT FLOWS
// ==========================================
app.get('/api/oauth/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, id_token_add_organizations } = req.query;

  const htmlContent = `
    <html>
      <head><title>Authorize Application</title></head>
      <body style="font-family: Arial, sans-serif; padding: 40px;">
        <h2>Authorize Application</h2>
        <p>Client ID: <strong>${client_id || 'Unknown'}</strong> is requesting access.</p>
        <form method="POST" action="/api/oauth/authorize/submit">
          <input type="hidden" name="client_id" value="${client_id || ''}" />
          <input type="hidden" name="redirect_uri" value="${redirect_uri || ''}" />
          <input type="hidden" name="state" value="${state || ''}" />
          <input type="hidden" name="scope" value="${scope || ''}" />
          <input type="hidden" name="code_challenge" value="${code_challenge || ''}" />
          <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}" />
          <input type="hidden" name="id_token_add_organizations" value="${id_token_add_organizations || ''}" />
          <div style="margin-bottom: 10px;">
            <label>Email:</label><br/>
            <input type="email" name="email" required style="width: 300px; padding: 8px;" />
          </div>
          <div style="margin-bottom: 10px;">
            <label>Password:</label><br/>
            <input type="password" name="password" required style="width: 300px; padding: 8px;" />
          </div>
          <button type="submit" style="padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer;">Authorize & Click</button>
        </form>
      </body>
    </html>`;
  res.send(htmlContent);
});

app.post('/api/oauth/authorize/submit', (req, res) => {
  const { email, password, client_id, redirect_uri, state, code_challenge } = req.body;
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).send('Invalid credentials');

  const authCode = crypto.randomBytes(16).toString('hex');
  authCodes.set(authCode, { userId: user.id, clientId: client_id, redirectUri: redirect_uri, codeChallenge: code_challenge });
  if (redirect_uri) {
    return res.redirect(`${redirect_uri}?code=${authCode}&state=${state || ''}`);
  }
  res.send(`Authorization code generated: ${authCode}`);
});

app.post('/oauth/device/authorize', (req, res) => {
  const { client_id, scope } = req.body;
  const deviceCode = crypto.randomBytes(16).toString('hex');
  const userCode = Math.random().toString(36).substring(2, 8).toUpperCase();
  const baseUrl = getBaseUrl(req);

  deviceCodes.set(deviceCode, { userCode, clientId: client_id, scope, status: 'pending', userId: null });
  res.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${baseUrl}/login/device`,
    verification_uri_complete: `${baseUrl}/login/device?user_code=${userCode}`,
    expires_in: 900,
    interval: 5
  });
});

app.get('/login/device', (req, res) => {
  const prefilledCode = req.query.user_code || '';
  const htmlContent = `<html>
    <head><title>Device Activation</title></head>
    <body style="font-family: Arial, sans-serif; padding: 40px;">
      <h2>Connect Your Device</h2>
      <form method="POST" action="/login/device">
        <div style="margin-bottom: 10px;">
          <label>Enter Device User Code:</label><br/>
          <input type="text" name="user_code" value="${prefilledCode}" required style="width: 300px; padding: 8px; text-transform: uppercase;" />
        </div>
        <div style="margin-bottom: 10px;">
          <label>Email:</label><br/>
          <input type="email" name="email" required style="width: 300px; padding: 8px;" />
        </div>
        <div style="margin-bottom: 10px;">
          <label>Password:</label><br/>
          <input type="password" name="password" required style="width: 300px; padding: 8px;" />
        </div>
        <button type="submit" style="padding: 10px 20px; background: #28a745; color: white; border: none; cursor: pointer;">Connect Account</button>
      </form>
    </body>
  </html>`;
  res.send(htmlContent);
});

app.post('/login/device', (req, res) => {
  const { user_code, email, password } = req.body;
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).send('Invalid email or password.');

  let foundKey = null;
  for (let [key, val] of deviceCodes.entries()) {
    if (val.userCode === user_code.toUpperCase()) {
      foundKey = key;
      val.status = 'approved';
      val.userId = user.id;
      break;
    }
  }
  if (!foundKey) return res.status(404).send('Invalid or expired user code.');
  res.send('<html><body style="font-family: Arial; padding: 40px;"><h2>Device successfully authorized! You can close this window.</h2></body></html>');
});

app.post('/oauth/device/code', (req, res) => {
  const { client_id, scope } = req.body;

  if (!client_id) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'client_id is required'
    });
  }

  const deviceCode = crypto.randomBytes(32).toString('hex');
  const userCode = crypto.randomBytes(4).toString('hex').toUpperCase().match(/.{1,4}/g).join('-');
  const baseUrl = getBaseUrl(req);
  const expiresIn = 900;

  deviceCodes.set(deviceCode, {
    userCode,
    clientId: client_id,
    scope: scope || 'openid profile email',
    status: 'pending',
    userId: null,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString()
  });

  res.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${baseUrl}/login/device`,
    verification_uri_complete: `${baseUrl}/login/device?user_code=${userCode}`,
    expires_in: expiresIn,
    interval: 5
  });
});

app.get('/oauth/device/code', (req, res) => {
  const deviceCodeList = [];

  for (let [deviceCode, data] of deviceCodes.entries()) {
    deviceCodeList.push({
      device_code: deviceCode,
      user_code: data.userCode,
      client_id: data.clientId,
      scope: data.scope,
      status: data.status,
      user_id: data.userId,
      created_at: data.createdAt,
      expires_at: data.expiresAt
    });
  }

  res.json({
    count: deviceCodeList.length,
    device_codes: deviceCodeList
  });
});

app.delete('/oauth/device/code', (req, res) => {
  const { device_code, user_code } = req.body;

  let deleted = false;
  let deletedCode = null;

  if (device_code) {
    if (deviceCodes.has(device_code)) {
      deletedCode = device_code;
      deviceCodes.delete(device_code);
      deleted = true;
    }
  } else if (user_code) {
    for (let [key, val] of deviceCodes.entries()) {
      if (val.userCode === user_code.toUpperCase() || val.userCode === user_code) {
        deletedCode = key;
        deviceCodes.delete(key);
        deleted = true;
        break;
      }
    }
  }

  if (!deleted) {
    return res.status(404).json({
      error: 'not_found',
      error_description: 'Device code not found. Provide device_code or user_code in request body.'
    });
  }

  res.json({
    message: 'Device code deleted successfully',
    deleted_device_code: deletedCode
  });
});

app.post('/oauth/token', (req, res) => {
  const { grant_type, device_code, client_id, client_secret, code, redirect_uri, code_verifier } = req.body;
  const baseUrl = getBaseUrl(req);

  if (grant_type === 'authorization_code') {
    const authSession = authCodes.get(code);
    if (!authSession) return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' });

    const appEntry = oauthApps.find(a => a.clientId === client_id);
    if (appEntry && appEntry.clientSecret !== client_secret) {
      return res.status(401).json({ error: 'invalid_client' });
    }

    if (authSession.codeChallenge && code_verifier) {
      const hashedVerifier = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      if (hashedVerifier !== authSession.codeChallenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Code verifier mismatch' });
      }
    }

    const accessToken = jwt.sign({ sub: authSession.userId }, JWT_SECRET, { expiresIn: '1h' });
    const idToken = jwt.sign(
      { sub: authSession.userId, iss: baseUrl, aud: client_id, organizations: [{ id: 'org_1' }] },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    issuedTokens.push({
      id: crypto.randomUUID(),
      access_token: accessToken,
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: authSession.scope || 'openid profile email',
      client_id: client_id,
      user_id: authSession.userId,
      grant_type: 'authorization_code',
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600 * 1000).toISOString()
    });

    authCodes.delete(code);
    return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600, id_token: idToken });
  }

  if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
    const deviceSession = deviceCodes.get(device_code);
    if (!deviceSession) return res.status(400).json({ error: 'invalid_grant' });

    if (deviceSession.status === 'pending') {
      return res.status(400).json({ error: 'authorization_pending' });
    }

    if (deviceSession.status === 'approved') {
      const accessToken = jwt.sign({ sub: deviceSession.userId }, JWT_SECRET, { expiresIn: '1h' });
      const idToken = jwt.sign(
        { sub: deviceSession.userId, iss: baseUrl, aud: client_id, organizations: [{ id: 'org_1' }] },
        JWT_SECRET,
        { expiresIn: '1h' }
      );

      issuedTokens.push({
        id: crypto.randomUUID(),
        access_token: accessToken,
        id_token: idToken,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: deviceSession.scope || 'openid profile email',
        client_id: client_id || deviceSession.clientId,
        user_id: deviceSession.userId,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 3600 * 1000).toISOString()
      });

      deviceCodes.delete(device_code);
      return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600, id_token: idToken });
    }
  }

  res.status(400).json({ error: 'unsupported_grant_type' });
});

// ==========================================
// TOKEN MANAGEMENT ENDPOINTS
// ==========================================

app.get('/oauth/token', (req, res) => {
  const { client_id, user_id } = req.query;

  let filteredTokens = [...issuedTokens];

  if (client_id) {
    filteredTokens = filteredTokens.filter(t => t.client_id === client_id);
  }
  if (user_id) {
    filteredTokens = filteredTokens.filter(t => t.user_id === user_id);
  }

  const maskedTokens = filteredTokens.map(t => ({
    ...t,
    access_token: t.access_token ? t.access_token.substring(0, 20) + '...' : null,
    id_token: t.id_token ? t.id_token.substring(0, 20) + '...' : null
  }));

  res.json({
    count: maskedTokens.length,
    tokens: maskedTokens
  });
});

app.delete('/oauth/token', (req, res) => {
  const { access_token, token_id } = req.body;

  let deleted = false;
  let deletedToken = null;

  if (token_id) {
    const index = issuedTokens.findIndex(t => t.id === token_id);
    if (index !== -1) {
      deletedToken = issuedTokens[index];
      issuedTokens.splice(index, 1);
      deleted = true;
    }
  } else if (access_token) {
    const index = issuedTokens.findIndex(t => t.access_token === access_token);
    if (index !== -1) {
      deletedToken = issuedTokens[index];
      issuedTokens.splice(index, 1);
      deleted = true;
    }
  }

  if (!deleted) {
    return res.status(404).json({
      error: 'not_found',
      error_description: 'Token not found. Provide access_token or token_id in request body.'
    });
  }

  if (deletedToken && deletedToken.access_token) {
    activeSessions.delete(deletedToken.access_token);
  }

  res.json({
    message: 'Token revoked successfully',
    revoked_token_id: deletedToken ? deletedToken.id : null
  });
});

// ==========================================
// API TOKEN MANAGEMENT ENDPOINTS
// ==========================================
app.post('/api/tokens', authenticateToken, (req, res) => {
  const { name } = req.body;
  const tokenId = crypto.randomUUID();
  const tokenVal = jwt.sign({ sub: req.user.sub, token_id: tokenId, type: 'api_token' }, JWT_SECRET);

  const tokenObj = { id: tokenId, name: name || 'API Token', token: tokenVal, userId: req.user.sub };
  apiTokens.push(tokenObj);
  res.status(201).json(tokenObj);
});

app.get('/api/tokens', authenticateToken, (req, res) => {
  const userTokens = apiTokens.filter(t => t.userId === req.user.sub);
  res.json(userTokens);
});

app.delete('/api/tokens/:id', authenticateToken, (req, res) => {
  const index = apiTokens.findIndex(t => t.id === req.params.id && t.userId === req.user.sub);
  if (index === -1) return res.status(404).json({ error: 'Token not found' });
  apiTokens.splice(index, 1);
  res.json({ message: 'API token deleted successfully' });
});

// ==========================================
// START SERVER
// ==========================================
app.listen(PORT, () => {
  console.log(`OAuth & Brevo Server running on port ${PORT}`);
});
