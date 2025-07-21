const express = require('express');
const cors = require('cors');
const authRoutes = require('./auth/routes/authRoutes');
const { authenticateToken } = require('./auth/middleware/authMiddleware');
require('dotenv').config();

const app = express();

// CORS configuration
app.use(cors({ 
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true
}));

app.use(express.json());

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`, req.body);
  next();
});

// Auth routes
app.use('/api/auth', authRoutes);

// Protected dashboard route
app.get('/dashboard', authenticateToken, (req, res) => {
  res.json({ 
    message: 'Welcome to the dashboard',
    user: req.user
  });
});


// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`CORS origin: ${process.env.CORS_ORIGIN || 'http://localhost:3000'}`);
});