const rateLimit = require("express-rate-limit");

//Login rate limit - 5 attempts per 15 minutes
exports.loginLimiter = rateLimit({
    windowMs : 15 * 60 * 1000, //15 minutes in milliseconds
    max : 5, // Max 5 attempts per window (15 minutes)
    message :{
        success : false,
        message : "Too many login attempts. Please try again after 15 minutes"
    } ,
    standardHeaders : true, // Send standard headers with the response headers
    legacyHeaders : false, // Disables the deprecated X-RateLimit headers
});

//Register rate limit - 5 accounts per hour

exports.registerLimiter = rateLimit({
    windowMs : 60 * 60 * 1000, //1 hour in milliseconds
    max : 5, // Max 5 accounts per hour
    message :{
        success : false,
        message : "Too many accounts created. Please try again after an hour"
    } ,
    standardHeaders : true, // Send standard headers with the response headers
    legacyHeaders : false, // Disables the deprecated X-RateLimit headers
});