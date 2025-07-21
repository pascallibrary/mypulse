const nodemailer = require('nodemailer');
require('dotenv').config();


const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS},
});

async function testEmail() {
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: 'test@example.com',
            subject: 'This is a test email.',
            text: 'This is a test email.',
        });
        console.log('Test email sent successfully');
    } catch(error){
        console.error('Error sending test email:', error)
    }
}

testEmail();