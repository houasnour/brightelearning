const User = require('../models/User');
const UserActivity = require('../models/UserActivity');
const crypto = require('crypto');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../services/emailService');
const useragent = require('express-useragent');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { version } = require('os');
const authTemplates = require('../services/authTemplates');

// function to get device info
const getDeviceInfo = (req) => {
    const ua = useragent.parse(req.headers[("user-agent")]);
    return {
        browser: {
            name: ua.browser,
            version: ua.version
        },
        os: {
            name: ua.os,
            version: ua.os_version || "Unknown",
        },
        device: ua.isMobile ? "Mobile" : "Desktop",
        isMobile: ua.isMobile,
        isDesktop: !ua.isMobile,
        isTablet: ua.isTablet,
    };
};

// Register User
//routes POST /api/auth/register
exports.register = async (req, res) => {
    // 🔹 LOG pour debug
    console.log("=== Début de l'inscription ===");
    console.log("Body reçu :", req.body);             // montre tout ce que le frontend envoie
    console.log("Headers reçus :", req.headers);      // montre les headers, utile pour user-agent, IP etc.
    console.log("IP du client :", req.ip);
    
    try {
        const {
            firstName,
            lastName,
            email,
            password,
            phoneNumber1,
        } = req.body;

        // Vérifie si toutes les données sont présentes
        if (!firstName || !lastName || !email || !password) {
            console.warn("Données manquantes !");
            return res.status(400).json({ success: false, message: "Tous les champs sont requis" });
        }

        //check if user exists
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({
                success: false,
                message: "Email already registered"
            });
        }

        //create verification token
        const verificationToken = crypto.randomBytes(32).toString("hex");
        const verificationTokenExpire = Date.now() + 24 * 60 * 60 * 1000; // 24h

        //create user
        const user = await User.create({
            firstName,
            lastName,
            email,
            password,
            phoneNumber1,
            verificationToken,
            verificationTokenExpire,
        });
        // //Creation of verification URL
        const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${verificationToken}`;
        //send verification email
        await sendVerificationEmail(email, firstName, verificationUrl);
        //Log user activity 
        const deviceInfo = getDeviceInfo(req);
        await UserActivity.create({
            user: user._id,
            action: "REGISTER",
            metadata: {
                ip: req.ip,
                userAgent: req.headers["user-agent"],
                device: deviceInfo.device,
                browser: deviceInfo.browser,
                location: req.headers["x-forwarded-for"] || req.connection.remoteAddress,

            },
            status: "SUCCESS",
        })
        //Send response
        res.status(201).json({
            success: true,
            message: "Registration successful, Please check your email to verify your account."
        })

    } catch (error) {
        console.error("Registration error : ", error)
        res.status(500).json({
            success: false,
            message: "An error occured during registration"
        })
    }
}

//Login
//routes POST /api/auth/login
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        //validate email & password
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "Please provide email and password" });
        }
        //check if user exists
        const user = await User.findOne({ email }).select("+password");
        if (!user) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        //check password
        const isMatch = await user.matchPassword(password);
        if (!isMatch) {
            //Log failed login attempt
            await UserActivity.create({
                user: user._id,
                action: "LOGIN",
                metadata: {
                    ip: req.ip,
                    userAgent: req.headers["user-agent"],
                    ...getDeviceInfo(req),
                    status: "FAILED",
                    details: "Invalid password",
                }
            })
        }
        //Check email verification
        if (!user.isEmailVerified) {
            return res.status(401).json({ success: false, message: "Please verify your email first" });
        }
        //generate JWT token
        const token = user.getSignedJwtToken();
        //Log successful login
        await UserActivity.create({
            user: user._id,
            action: "LOGIN",
            metadata: {
                ip: req.ip,
                userAgent: req.headers["user-agent"],
                ...getDeviceInfo(req),
            },
            status: "SUCCESS",
        })
        //return response
        res.status(200).json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                role: user.role,
                isProfileComplete: user.isProfileComplete,

            }
        })


    } catch (error) {
        console.error("Login error : ", error)
        res.status(500).json({
            success: false,
            message: "An error occured during Login"
        })
    }
}

//Refresh access token
//routes POST /api/auth/refresh-token
exports.refreshToken = async (res, req) => {
    try {
        //extract the refresh token
        const { refreshToken } = req.body;
        //check if refresh token exists
        if (!refreshToken) {
            return res.status(400).json({ success: false, message: "Refresh token is required" });
        }
        //verify refresh token
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);
        //if user doesn't exist
        if (!user) {
            return res.status(401).json({ success: false, message: "User not found" });
        }
        //generate new access token
        const accessToken = user.getSignedJwtToken();
        //Log user activity
        await UserActivity.create({
            user: user._id,
            action: "TOKEN_REFRESH",
            metadata: {
                ip: req.ip,
                userAgent: req.headers["user-agent"],
                ...getDeviceInfo(req),
            },
            status: "SUCCESS",
        })
        // Return the new token
        res.status(200).json({
            success: true,
            accessToken,
        })
    } catch (error) {
        console.error("Token refresh error : ", error);
        res.status(401).json({
            success: false,
            message: "Invalid or expired refresh token"
        })
    }
}

//get all users (only admin)
// routes GET /api/auth/users
exports.getAllUsers = async (req, res) => {
    try {
        const users = await User.find().select("-password");
        res.status(200).json({
            success: true,
            count: users.length,
            data: users
        })
    } catch (error) {
        console.error("Get all users error : ", error);
        res.status(500).json({
            success: false,
            message: "An error occured while fetching users"
        })
    }
}

// Get logged in user
// route GET /api/auth/me
exports.getMe = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("-password");
        res.status(200).json({
            success: true,
            data: user
        })
    } catch (error) {
        console.error("Get me error : ", error);
        res.status(500).json({
            success: false,
            message: "An error occured while data me"
        })
    }
}

//logout
// route POST /api/auth/logout
exports.logout = async (req, res) => {
    try {
        await UserActivity.create({
            user: req.user.id,
            action: "LOGOUT",
            deviceInfo: getDeviceInfo(req),
            sessionData: {
                userAgent: req.headers["user-agent"],
            },
            status: "SUCCESS",
        });
        res.status(200).json({
            success: true,
            message: "Logged out successfully"
        })
    } catch (error) {
        console.error("logout error : ", error);
        res.status(500).json({
            success: false,
            message: "An error occured while logging out"
        })
    }
}

exports.verifyEmail = async (req, res) => {
    try {
        const user = await User.findOne({
            verificationToken: req.params.token,
            verificationTokenExpire: { $gt: Date.now() }
        })
        if (!user) {
            return res.redirect(`${process.env.FRONTEND_URL}/verification-failed`);
        }
        user.isEmailVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpire = undefined;
        await user.save();
        //Log verification success
        await UserActivity.create({
            user: user._id,
            action: "EMAIL_VERIFIED",
            deviceInfo: getDeviceInfo(req),
            sessionData: {
                userAgent: req.headers["user-agent"],
            },
            status: "SUCCESS",
        });
        res.redirect(`${process.env.FRONTEND_URL}/verification-success`);
    } catch (error) {
        console.error("Email verification error : ", error);
        res.redirect(`${process.env.FRONTEND_URL}/verification-error`);
    }
}
exports.resendVerification = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }
        if (user.isEmailVerified) {
            return res.status(400).json({ success: false, message: "Email already verified" });
        }
        //Create new verification token
        const verificationToken = crypto.randomBytes(32).toString("hex");
        user.verificationToken = verificationToken;
        user.verificationTokenExpire = Date.now() + 24 * 60 * 60 * 1000; //24h
        await user.save();
        //Send new verification email
        const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${verificationToken}`;
        await sendVerificationEmail(user.email, user.firstName, verificationUrl);
        res.status(200).json({
            success: true,
            message: "Verification email resent successfully"
        })
    } catch (error) {
        console.error("Resend verification error : ", error);
        res.status(500).json({
            success: false,
            message: "An error occured while resending verification email"
        })
    }
}

//Forgot Password
// POST /api/auth/forgot-password

exports.forgotPassword = async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }
        //Generate token
        const resetToken = crypto.randomBytes(32).toString("hex");
        user.resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");
        user.resetPasswordExpire = Date.now() + 60 * 60 * 1000; //1 hour
        await user.save();
        //Create reset url
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
        await sendPasswordResetEmail(user.email, user.name, resetUrl);
        //Activity log
        await UserActivity.create({
            user: user._id,
            action: "PASSWORD_RESET",
            deviceInfo: getDeviceInfo(req),
            sessionData: {
                userAgent: req.headers["user-agent"],
                timestamp: Date.now(),

            },
            status: "PENDING"
        })
        res.status(200).json({
            success: true,
            message: "Password reset email sent"
        });
    } catch (error) {
        console.error("Resend Password Reset error : ", error);
        res.status(500).json({
            success: false,
            message: "An error occured while resending Password Reset email"
        })
    }
}

// Reset password
// route PUT /api/auth/reset-password/:token
exports.resetPassword = async (req, res) => {
    try {
        const resetToken = req.params.token;
        console.log("Reset token from params:", resetToken);
        const resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");
        console.log("Hashed token:", resetPasswordToken);
        const user = await User.findOne({
            resetPasswordToken,
            resetPasswordExpire: { $gt: Date.now() }
        })
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "Invalid or expired reset token"
            })
        }
        // set new password
        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save();

        //Log activity
        await UserActivity.create({
            user : user._id,
            action : "PASSWORD_RESET",
            deviceInfo : getDeviceInfo(req),
            sessionData : {
                userAgent : req.headers["user-agent"],
                timestamp : Date.now(),
            },
            status : "SUCCESS"
        });
        //sending response
        res.status(200).json({
            success : true,
            message : "Password reset successful"
        })


    } catch (error) {
        console.error("Reset Password error : ", error);
        res.status(500).json({
            success: false,
            message: "An error occured while Password Reset"
        })
    }
}
// GET /api/auth/google
exports.googleAuth = passport.authenticate("google", { 
    scope: ["profile", "email"] 
});
// Google OAuth Callback
// route GET /api/auth/google/callback
exports.googleCallback = (req,res,next) => {
    passport.authenticate("google", (err,user) => {
        if (err) {
            console.error("Google auth error : ", err);
            return res.send(
                authTemplates.errorPage("Failed to authenticate with Google.")
            );
        }
        if(!user){
            return res.send(authTemplates.userNotFoundPage());
        }

        const token = user.getSignedJwtToken();

        // Log successful login
        UserActivity.create({
            user : user._id,
            action : "LOGIN",
            metadata : {
                ip : req.ip,
                userAgent : req.headers["user-agent"],
                provider : "google",
                ...getDeviceInfo(req),
            },
            status : "SUCCESS",
        });
        // Send success page
        res.send(authTemplates.successPage(user,token));

        /* Front end redirect code (kept for later use)
        if(req.headers.accept?.includes("application/json")){
            return res.json({
                success : true,
                token,
                user : {
                    id : user._id,
                    email : user.email,
                    isProfileComplete : user.isProfileComplete,
                }
            });
        }
            res.redirect(`${process.env.FRONTEND_URL}/auth/success?token=${token}`);
        */
    }) (req,res,next);
}