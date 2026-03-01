/**
 * HTML templates for OAuth authentication responses
 */

/**
 * Success page shown after successful authentication
 * @param {Object} user - The authenticated user
 * @param {String} token - JWT token
 * @returns {String} HTML content
 */
exports.successPage = (user, token) => {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentication Successful | Bright elerning </title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: 'Inter', sans-serif;
      background-color: #f5f7fa;
      color: #333;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      padding: 20px;
    }
    .container {
      background-color: white;
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
      width: 100%;
      max-width: 500px;
      padding: 40px;
      text-align: center;
      animation: fadeIn 0.5s ease-out;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .success-icon {
      width: 80px;
      height: 80px;
      background-color: #e7f5ee;
      border-radius: 50%;
      display: flex;
      justify-content: center;
      align-items: center;
      margin: 0 auto 20px;
    }
    h1 {
      font-size: 24px;
      font-weight: 600;
      margin-bottom: 12px;
      color: #111827;
    }
    p {
      font-size: 16px;
      color: #6b7280;
      margin-bottom: 24px;
      line-height: 1.6;
    }
    .user-info {
      background-color: #f9fafb;
      padding: 16px;
      border-radius: 8px;
      margin-bottom: 24px;
      text-align: left;
    }
    .user-info p {
      margin-bottom: 8px;
      font-size: 14px;
    }
    .user-info strong {
      color: #111827;
    }
    .button {
      display: inline-block;
      background-color: #2563eb;
      color: white;
      font-weight: 500;
      padding: 12px 24px;
      border-radius: 8px;
      text-decoration: none;
      transition: background-color 0.2s;
    }
    .button:hover {
      background-color: #1d4ed8;
    }
    .button:active {
      transform: translateY(1px);
    }
    .token-info {
      margin-top: 24px;
      font-size: 13px;
      color: #9ca3af;
    }
    .token {
      background-color: #f1f5f9;
      padding: 8px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 12px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      margin-top: 8px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="success-icon">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22C17.5228 22 22 17.5228 22 12Z" stroke="#10B981" stroke-width="2"/>
        <path d="M8 12L10.5 14.5L16 9" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <h1>Authentication Successful</h1>
    <p>You have successfully signed in with your Google account.</p>
    
    <div class="user-info">
      <p><strong>Name:</strong> ${user.firstName} ${user.lastName || ''}</p>
      <p><strong>Email:</strong> ${user.email}</p>
    </div>
    
    <a href="${process.env.FRONTEND_URL || '/'}" class="button">Continue to Nexamart</a>
    
    <div class="token-info">
      <p>Authentication token (for development only):</p>
      <div class="token">${token.substring(0, 20)}...</div>
    </div>
  </div>
</body>
</html>`;
};

/**
 * Error page shown when authentication fails
 * @param {String} message - Error message
 * @returns {String} HTML content
 */
exports.errorPage = (message) => {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentication Failed | Nexamart</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: 'Inter', sans-serif;
      background-color: #f5f7fa;
      color: #333;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      padding: 20px;
    }
    .container {
      background-color: white;
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
      width: 100%;
      max-width: 500px;
      padding: 40px;
      text-align: center;
      animation: fadeIn 0.5s ease-out;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .error-icon {
      width: 80px;
      height: 80px;
      background-color: #fee2e2;
      border-radius: 50%;
      display: flex;
      justify-content: center;
      align-items: center;
      margin: 0 auto 20px;
    }
    h1 {
      font-size: 24px;
      font-weight: 600;
      margin-bottom: 12px;
      color: #111827;
    }
    p {
      font-size: 16px;
      color: #6b7280;
      margin-bottom: 24px;
      line-height: 1.6;
    }
    .error-message {
      background-color: #fef2f2;
      border-left: 4px solid #ef4444;
      padding: 16px;
      border-radius: 4px;
      margin-bottom: 24px;
      text-align: left;
      color: #b91c1c;
    }
    .button {
      display: inline-block;
      background-color: #2563eb;
      color: white;
      font-weight: 500;
      padding: 12px 24px;
      border-radius: 8px;
      text-decoration: none;
      transition: background-color 0.2s;
      margin-right: 12px;
    }
    .button:hover {
      background-color: #1d4ed8;
    }
    .button:active {
      transform: translateY(1px);
    }
    .secondary-button {
      display: inline-block;
      background-color: #f3f4f6;
      color: #4b5563;
      font-weight: 500;
      padding: 12px 24px;
      border-radius: 8px;
      text-decoration: none;
      transition: background-color 0.2s;
    }
    .secondary-button:hover {
      background-color: #e5e7eb;
    }
    .secondary-button:active {
      transform: translateY(1px);
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="error-icon">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 8V12M12 16H12.01M22 12C22 17.5228 17.5228 22 12 22C6.47715 22 2 17.5228 2 12C2 6.47715 6.47715 2 12 2C17.5228 2 22 6.47715 22 12Z" stroke="#DC2626" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <h1>Authentication Failed</h1>
    <p>We couldn't authenticate you with Google. Please try again or use another method to sign in.</p>
    
    <div class="error-message">
      ${message || 'An unexpected error occurred during authentication.'}
    </div>
    
    <a href="${process.env.FRONTEND_URL}/login" class="button">Try Again</a>
    <a href="${process.env.FRONTEND_URL || '/'}" class="secondary-button">Back to Home</a>
  </div>
</body>
</html>`;
};

/**
 * User not found page
 * @returns {String} HTML content
 */
exports.userNotFoundPage = () => {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Not Found | Nexamart</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: 'Inter', sans-serif;
      background-color: #f5f7fa;
      color: #333;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      padding: 20px;
    }
    .container {
      background-color: white;
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
      width: 100%;
      max-width: 500px;
      padding: 40px;
      text-align: center;
      animation: fadeIn 0.5s ease-out;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .user-icon {
      width: 80px;
      height: 80px;
      background-color: #e0f2fe;
      border-radius: 50%;
      display: flex;
      justify-content: center;
      align-items: center;
      margin: 0 auto 20px;
    }
    h1 {
      font-size: 24px;
      font-weight: 600;
      margin-bottom: 12px;
      color: #111827;
    }
    p {
      font-size: 16px;
      color: #6b7280;
      margin-bottom: 24px;
      line-height: 1.6;
    }
    .steps-container {
      background-color: #f8fafc;
      padding: 20px;
      border-radius: 8px;
      text-align: left;
      margin-bottom: 24px;
    }
    .steps-container h2 {
      font-size: 16px;
      color: #475569;
      margin-bottom: 12px;
    }
    .step {
      display: flex;
      margin-bottom: 12px;
      align-items: flex-start;
    }
    .step-number {
      background-color: #bfdbfe;
      color: #1e40af;
      width: 24px;
      height: 24px;
      border-radius: 50%;
      display: flex;
      justify-content: center;
      align-items: center;
      font-weight: 600;
      font-size: 14px;
      margin-right: 12px;
      flex-shrink: 0;
    }
    .step-text {
      font-size: 14px;
      color: #4b5563;
    }
    .button-container {
      display: flex;
      gap: 12px;
      justify-content: center;
    }
    .button {
      flex: 1;
      display: inline-block;
      background-color: #2563eb;
      color: white;
      font-weight: 500;
      padding: 12px 24px;
      border-radius: 8px;
      text-decoration: none;
      transition: background-color 0.2s;
      max-width: 200px;
    }
    .button:hover {
      background-color: #1d4ed8;
    }
    .button:active {
      transform: translateY(1px);
    }
    .secondary-button {
      flex: 1;
      display: inline-block;
      background-color: #f3f4f6;
      color: #4b5563;
      font-weight: 500;
      padding: 12px 24px;
      border-radius: 8px;
      text-decoration: none;
      transition: background-color 0.2s;
      max-width: 200px;
    }
    .secondary-button:hover {
      background-color: #e5e7eb;
    }
    .secondary-button:active {
      transform: translateY(1px);
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="user-icon">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M20 21V19C20 16.7909 18.2091 15 16 15H8C5.79086 15 4 16.7909 4 19V21M16 7C16 9.20914 14.2091 11 12 11C9.79086 11 8 9.20914 8 7C8 4.79086 9.79086 3 12 3C14.2091 3 16 4.79086 16 7Z" stroke="#0369A1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <h1>User Not Found</h1>
    <p>We couldn't find an account associated with this Google profile. You may need to register first.</p>
    
    <div class="steps-container">
      <h2>What you can do:</h2>
      <div class="step">
        <div class="step-number">1</div>
        <div class="step-text">Register a new account using the same email address</div>
      </div>
      <div class="step">
        <div class="step-number">2</div>
        <div class="step-text">Use a different sign-in method if you already have an account</div>
      </div>
      <div class="step">
        <div class="step-number">3</div>
        <div class="step-text">Contact support if you believe this is an error</div>
      </div>
    </div>
    
    <div class="button-container">
      <a href="${process.env.FRONTEND_URL}/register" class="button">Register</a>
      <a href="${process.env.FRONTEND_URL}/login" class="secondary-button">Sign In</a>
    </div>
  </div>
</body>
</html>`;
};