const express = require("express");
const router = express.Router();
const { loginLimiter, registerLimiter } = require("../middleware/rateLimiter");
const { protect, authorize } = require("../middleware/auth");
const { validatorRegister, validateForgetPassword, validateResetPassword } = require("../middleware/validator");

const {
    register,
    login,
    verifyEmail,
    refreshToken,
    getMe,
    logout,
    getAllUsers,
    resendVerification,
    forgotPassword,
    resetPassword,
    googleCallback,
    googleAuth
} = require("../controllers/authControllers");
//Public routes
router.post("/register", registerLimiter, validatorRegister, register);

router.post("/login", loginLimiter, login);
router.get("/verify-email/:token", verifyEmail);
router.post("/resend-verification", loginLimiter, resendVerification);
router.post("/forgot-password", validateForgetPassword, forgotPassword);
router.put("/reset-password/:token", validateResetPassword, resetPassword);

//Google OAuth routes
router.get("/google", googleAuth);
router.get("/google/callback", googleCallback);
// Protected routes
router.use(protect); //apply to all routes below this line
router.post("/refresh-token", refreshToken);
router.get("/me", getMe);
router.post("/logout", logout);

//only admin
router.get("/users", authorize("admin"), getAllUsers);

module.exports = router;