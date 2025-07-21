const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../utils/db');
const { sendVerificationEmail, sendResetPasswordEmail } = require('../services/emailServices');
require('dotenv').config();

const register = async (req, res) => {
  const { email, password, username } = req.body;
  
  // Input validation
  if (!email || !password || !username) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters long' });
  }

  try {
    // Check if email already exists
    const emailCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (emailCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Check if username already exists
    const usernameCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (usernameCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    
    await pool.query(
      'INSERT INTO users (username, email, password, is_verified) VALUES ($1, $2, $3, $4)',
      [username, email, hashedPassword, false]
    );
    
    // Try to send verification email, but don't fail registration if email fails
    try {
      await sendVerificationEmail(email, verificationToken);
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
      // Continue with registration even if email fails
    }
    
    res.status(201).json({ message: 'Registration successful! Please check your email to verify.' });
  } catch (error) {
    console.error('Registration error:', error);
    
    if (error.code === '23505') {
      if (error.constraint === 'users_email_key') {
        return res.status(400).json({ message: 'Email already exists' });
      }
      if (error.constraint === 'users_username_key') {
        return res.status(400).json({ message: 'Username already exists' });
      }
    }
    
    res.status(500).json({ message: 'Error registering user' });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  // Input validation
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    
    if (!user.is_verified) {
      return res.status(400).json({ message: 'Please verify your email first' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    
    res.json({ 
      token, 
      redirect: '/dashboard',
      user: { id: user.id, email: user.email, username: user.username }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Error logging in' });
  }
};

const verifyEmail = async (req, res) => {
  const { token } = req.query;
  
  if (!token) {
    return res.status(400).json({ message: 'Verification token is required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [decoded.email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }
    
    await pool.query('UPDATE users SET is_verified = TRUE WHERE email = $1', [decoded.email]);
    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error('Verify email error:', error);
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Verification token has expired' });
    }
    res.status(400).json({ message: 'Invalid verification token' });
  }
};

const requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (!user) {
      return res.status(400).json({ message: 'Email not found' });
    }
    
    const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    
    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3',
      [resetToken, new Date(Date.now() + 3600000), email]
    );
    
    try {
      await sendResetPasswordEmail(email, resetToken);
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
    }
    
    res.json({ message: 'Password reset link sent to your email' });
  } catch (error) {
    console.error('Request password reset error:', error);
    res.status(500).json({ message: 'Error requesting password reset' });
  }
};

const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  
  if (!token || !newPassword) {
    return res.status(400).json({ message: 'Token and new password are required' });
  }
  
  if (newPassword.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters long' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND reset_token = $2 AND reset_token_expiry > $3',
      [decoded.email, token, new Date()]
    );
    
    const user = result.rows[0];
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    await pool.query(
      'UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE email = $2',
      [hashedPassword, decoded.email]
    );
    
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Reset token has expired' });
    }
    res.status(500).json({ message: 'Error resetting password' });
  }
};

module.exports = {
  register,
  login,
  verifyEmail,
  requestPasswordReset,
  resetPassword
};