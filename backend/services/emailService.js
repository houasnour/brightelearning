const nodemailer = require("nodemailer");

const createVerificationEmailTemplate = (firstname, verificationUrl) => {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Email Verification</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          margin: 0;
          padding: 0;
          background-color: #f9f9f9;
          color: #333333;
          line-height: 1.6;
        }
        .container {
          max-width: 600px;
          margin: 0 auto;
          padding: 0;
          background-color: #ffffff;
          border-radius: 12px;
          box-shadow: 0 6px 18px rgba(0, 0, 0, 0.08);
          overflow: hidden;
        }
        .header {
          text-align: center;
          padding: 35px 0;
          background: linear-gradient(135deg, #4a6cf7 0%, #6a3ef8 100%);
          color: white;
        }
        .logo {
          font-size: 32px;
          font-weight: bold;
          letter-spacing: 1px;
          margin-bottom: 5px;
        }
        .tagline {
          font-size: 14px;
          opacity: 0.9;
        }
        .content {
          padding: 40px 30px;
          line-height: 1.7;
          color: #333333;
        }
        .highlight {
          font-weight: 600;
          color: #4a6cf7;
        }
        .button {
          display: inline-block;
          padding: 14px 28px;
          background: linear-gradient(to right, #4a6cf7, #6a3ef8);
          color: #ffffff !important;
          text-decoration: none;
          border-radius: 6px;
          font-weight: 600;
          margin: 25px 0;
          text-align: center;
          transition: all 0.3s ease;
          box-shadow: 0 4px 10px rgba(74, 108, 247, 0.3);
        }
        .button:hover {
          transform: translateY(-2px);
          box-shadow: 0 6px 15px rgba(74, 108, 247, 0.4);
        }
        .link-container {
          background-color: #f5f7ff;
          border-radius: 6px;
          padding: 15px;
          margin: 20px 0;
        }
        .footer {
          text-align: center;
          padding: 25px 20px;
          font-size: 13px;
          color: #999999;
          border-top: 1px solid #eeeeee;
          background-color: #fafafa;
        }
        @media only screen and (max-width: 600px) {
          .container {
            width: 100%;
            border-radius: 0;
          }
          .content {
            padding: 30px 20px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="logo">NexaMart</div>
          <div class="tagline">Your One-Stop Shopping Destination</div>
        </div>
        <div class="content">
          <h2>Hello <span class="highlight">${firstname}</span>!</h2>
          <p><strong>Thank you for signing up with NexaMart.</strong> We're excited to have you on board!</p>
          <p>To complete your registration and verify your email address, please click the button below:</p>
          
          <div style="text-align: center;">
            <a href="${verificationUrl}" class="button">Verify Email Address</a>
          </div>
          
          <p>If the button doesn't work, you can also copy and paste the following link into your browser:</p>
          <div class="link-container">
            <p style="word-break: break-all; font-size: 14px; color: #666666;">${verificationUrl}</p>
          </div>
          
          <p><strong>This verification link will expire in 24 hours.</strong></p>
          
          <p>If you didn't create an account with NexaMart, you can safely ignore this email.</p>
          
          <p><strong>Best regards,</strong><br>The NexaMart Team</p>
        </div>
        <div class="footer">
          <p>&copy; ${new Date().getFullYear()} NexaMart. All rights reserved.</p>
          <p>This is an automated email, please do not reply.</p>
        </div>
      </div>
    </body>
    </html>
  `;
}

// reset Password Template
const createPasswordResetTemplate = (firstName, resetUrl) => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        .email-container {
          max-width: 600px;
          margin: 0 auto;
          font-family: Arial, sans-serif;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .header {
          background: linear-gradient(to right, #ef4444, #dc2626);
          padding: 30px;
          text-align: center;
          color: white;
          border-radius: 8px 8px 0 0;
        }
        .logo {
          font-size: 32px;
          font-weight: bold;
          margin: 0;
        }
        .content {
          padding: 40px;
          background: white;
          border: 1px solid #e5e7eb;
        }
        .alert-box {
          background: #fee2e2;
          border: 1px solid #ef4444;
          padding: 15px;
          border-radius: 8px;
          margin: 20px 0;
          color: #991b1b;
        }
        .welcome-text {
          font-size: 24px;
          color: #1f2937;
          margin-bottom: 20px;
        }
        .button {
          background: linear-gradient(to right, #ef4444, #dc2626);
          color: white;
          padding: 15px 30px;
          text-decoration: none;
          border-radius: 8px;
          display: inline-block;
          margin: 20px 0;
          font-weight: bold;
          transition: transform 0.2s;
        }
        .button:hover {
          transform: translateY(-2px);
        }
        .footer {
          text-align: center;
          padding: 20px;
          background: #f3f4f6;
          color: #6b7280;
          font-size: 0.875rem;
          border-radius: 0 0 8px 8px;
        }
        .security-tips {
          background: #f3f4f6;
          padding: 15px;
          border-radius: 8px;
          margin: 20px 0;
        }
        .security-tips ul {
          margin: 10px 0;
          padding-left: 20px;
        }
        .expiry-warning {
          color: #991b1b;
          font-weight: bold;
        }
      </style>
    </head>
    <body>
      <div class="email-container">
        <div class="header">
          <h1 class="logo">NexaMart</h1>
        </div>
        <div class="content">
          <h2 class="welcome-text">Password Reset Request</h2>
          <p>Hello ${firstName},</p>
          <p>We received a request to reset your password for your NexaMart account.</p>
          
          <div class="alert-box">
            <strong>⚠️ IMPORTANT:</strong> If you didn't request this password reset, please:
            <ul>
              <li>Ignore this email</li>
              <li>Secure your account immediately</li>
              <li>Contact our support team</li>
            </ul>
          </div>

          <p>If you did request this reset, click the button below:</p>
          <div style="text-align: center;">
            <a href="${resetUrl}" class="button">Reset Password</a>
          </div>
          
          <p class="expiry-warning">⏰ This link will expire in 1 hour for security reasons.</p>

          <div class="security-tips">
            <strong>🔒 Security Tips:</strong>
            <ul>
              <li>Never share your password with anyone</li>
              <li>Create a strong, unique password</li>
              <li>Enable two-factor authentication if available</li>
              <li>Regularly update your security information</li>
            </ul>
          </div>

          <p style="word-break: break-all; color: #6b7280; font-size: 0.875rem;">
            If the button doesn't work, copy and paste this link: ${resetUrl}
          </p>
        </div>
        <div class="footer">
          <p>© ${new Date().getFullYear()} NexaMart. All rights reserved.</p>
          <p>This email was sent to you because a password reset was requested for your account.</p>
          <p>If you have any concerns, please contact our support team immediately.</p>
        </div>
      </div>
    </body>
    </html>
  `;
};

//Create transporter
const transporter = nodemailer.createTransport({

  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
})

//Sending verification email
const sendVerificationEmail = async (email, name, verificationUrl) => {
  const mailOptions = {
    from: ` brightelerning <${process.env.SMTP_USER}>`,
    to: email,
    subject: "Welcome to brightelerning - Verify Your Email",
    html: createVerificationEmailTemplate(name, verificationUrl)
  };
  await transporter.sendMail(mailOptions);
};

const sendPasswordResetEmail = async (email, firstName, resetUrl) => {
  const mailOptions = {
    form: `"brightelerning Security" <${process.env.SMTP_USER}> `,
    to: email,
    subject: "🔏🔒  Passord Reset Request - Action Required",
    html: createPasswordResetTemplate(firstName, resetUrl),
  };
  await transporter.sendMail(mailOptions);
};


module.exports = { sendVerificationEmail, sendPasswordResetEmail };