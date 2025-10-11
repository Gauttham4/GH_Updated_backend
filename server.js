// server.js - Node.js Backend for OTP Service
const express = require('express');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const SERVER_URL = process.env.SERVER_URL;
// Middleware
app.use(cors());
app.use(express.json());

// Store OTPs temporarily (in production, use Redis or database)
const otpStore = new Map();

// Email configuration using nodemailer
const emailTransporter = nodemailer.createTransport({
  service: 'gmail', // or your email service
  auth: {
    user: process.env.EMAIL_USER, // Your email
    pass: process.env.EMAIL_PASS, // Your app password
  },
});

// Twilio configuration for SMS
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// Generate 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Store OTP with expiration (10 minutes)
function storeOTP(identifier, otp) {
  const expirationTime = Date.now() + 10 * 60 * 1000; // 10 minutes
  otpStore.set(identifier, {
    otp: otp,
    expiresAt: expirationTime,
    attempts: 0
  });
}

// Verify OTP
function verifyOTP(identifier, otp) {
  const storedData = otpStore.get(identifier);
  
  if (!storedData) {
    return { success: false, message: 'OTP not found or expired' };
  }
  
  if (Date.now() > storedData.expiresAt) {
    otpStore.delete(identifier);
    return { success: false, message: 'OTP has expired' };
  }
  
  if (storedData.attempts >= 3) {
    otpStore.delete(identifier);
    return { success: false, message: 'Maximum attempts exceeded' };
  }
  
  if (storedData.otp !== otp) {
    storedData.attempts++;
    return { success: false, message: 'Invalid OTP' };
  }
  
  // OTP is valid, remove it from store
  otpStore.delete(identifier);
  return { success: true, message: 'OTP verified successfully' };
}

// Send OTP via Email
app.post('/send-email-otp', async (req, res) => {
  try {
    const { email, userName } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }
    
    const otp = generateOTP();
    storeOTP(email, otp);
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP for Login - Mindora',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #4CAF50, #45a049); color: white; padding: 20px; border-radius: 10px 10px 0 0; text-align: center;">
            <h1 style="margin: 0; font-size: 24px;">Mindora</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">Secure Login Verification</p>
          </div>
          
          <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
            <h2 style="color: #333; margin-top: 0;">Hello ${userName || 'User'}!</h2>
            
            <p style="color: #666; font-size: 16px; line-height: 1.5;">
              You requested to log in to your account. Please use the following OTP to complete your login:
            </p>
            
            <div style="background: white; border: 2px dashed #4CAF50; border-radius: 10px; padding: 20px; text-align: center; margin: 20px 0;">
              <h1 style="color: #4CAF50; font-size: 32px; letter-spacing: 5px; margin: 0; font-family: 'Courier New', monospace;">
                ${otp}
              </h1>
            </div>
            
            <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 15px; margin: 20px 0;">
              <p style="margin: 0; color: #856404; font-size: 14px;">
                <strong>⚠️ Important:</strong> This OTP will expire in 10 minutes. Do not share this code with anyone.
              </p>
            </div>
            
            <p style="color: #666; font-size: 14px; line-height: 1.5;">
              If you didn't request this OTP, please ignore this email and ensure your account is secure.
            </p>
            
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            
            <p style="color: #999; font-size: 12px; text-align: center;">
              This is an automated message from Education App. Please do not reply to this email.
            </p>
          </div>
        </div>
      `
    };
    
    await emailTransporter.sendMail(mailOptions);
    
    res.json({ 
      success: true, 
      message: 'OTP sent successfully to your email',
      expiresIn: '10 minutes'
    });
    
  } catch (error) {
    console.error('Email sending error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send OTP email' 
    });
  }
});

// Send OTP via SMS
app.post('/send-sms-otp', async (req, res) => {
  try {
    const { phone, userName } = req.body;
    
    if (!phone) {
      return res.status(400).json({ 
        success: false, 
        message: 'Phone number is required' 
      });
    }
    
    const otp = generateOTP();
    storeOTP(phone, otp);
    
    const message = `Hello ${userName || 'User'}! Your OTP for Education App login is: ${otp}. This code will expire in 10 minutes. Do not share this code with anyone.`;
    
    await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone
    });
    
    res.json({ 
      success: true, 
      message: 'OTP sent successfully to your phone',
      expiresIn: '10 minutes'
    });
    
  } catch (error) {
    console.error('SMS sending error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send OTP SMS' 
    });
  }
});

// Verify OTP
app.post('/verify-otp', (req, res) => {
  try {
    const { identifier, otp } = req.body;
    
    if (!identifier || !otp) {
      return res.status(400).json({ 
        success: false, 
        message: 'Identifier and OTP are required' 
      });
    }
    
    const result = verifyOTP(identifier, otp);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
    
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to verify OTP' 
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
// Start server
app.listen(PORT, SERVER_URL, () => {
  console.log(`OTP Service running on http://${SERVER_URL}:${PORT}`);
});

// Cleanup expired OTPs every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [identifier, data] of otpStore.entries()) {
    if (now > data.expiresAt) {
      otpStore.delete(identifier);
    }
  }
}, 5 * 60 * 1000);