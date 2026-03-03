const jwt = require("jsonwebtoken");
const User = require("../models/User");

// Checks if an Authorization header exists and starts with Bearer
// Extracts the JWT token from the header
// Verifies the token using jwt.verify()
// Decodes the token and finds the user in the database (User.findById())
// Attaches the user object to req.user so it can be accessed in protected routes
// Calls next() to proceed to next middleware/controller
// if the token is missing or invalid, it sends a 401 unauthorized error

exports.protect = async (req, res, next) => {
    try {
        let token;
        if (
            req.headers.authorization &&
            req.headers.authorization.startsWith("Bearer")
        ) {
            token = req.headers.authorization.split(" ")[1];
        }

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Not authorized to access this route"
            })
        }
        try {
            //Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = await User.findById(decoded.id);
            next();
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: "Not authorized to access this route"
            })
        }
    } catch (error) {
        console.error("Auth middleware error : ", error);
        res.status(500).json({
            success: false,
            message: "Server error"
        })
    }
}

exports.authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: `User role ${req.user.role} is not authorized to access this route`
            });
        }
        next();
    };
};