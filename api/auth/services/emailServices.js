const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

const sendVerificationEmail = async (email, token) => {
  try {
    const verificationUrl = `http://localhost:3000/auth/verify?token=${token}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Email',
      text: `Please verify your email by clicking this link: ${verificationUrl}`,
    });
    console.log(`Verification email sent to ${email}`);
  } catch (error) {
    console.error(`Error sending verification email to ${email}:`, error);
    throw error;
  }
};

const sendResetPasswordEmail = async (email, token) => {
  try {
    const resetUrl = `http://localhost:3000/auth/reset-password?token=${token}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Reset Your Password',
      text: `Click this link to reset your password: ${resetUrl}. This link expires in 1 hour.`,
    });
    console.log(`Reset password email sent to ${email}`);
  } catch (error) {
    console.error(`Error sending reset password email to ${email}:`, error);
    throw error;
  }
};

module.exports = { sendVerificationEmail, sendResetPasswordEmail };