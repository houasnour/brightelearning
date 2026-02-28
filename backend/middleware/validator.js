const { check, validationResult } = require("express-validator");

exports.validatorRegister = [
    check("firstlName")
        .trim()
        .notEmpty()
        .withMessage("Full Name is required")
        .isLength({ max: 25 })
        .withMessage("First Name should not exceed 25 characters"),
    check("lastlName")
        .trim()
        .notEmpty()
        .withMessage("Full Name is required")
        .isLength({ max: 25 })
        .withMessage("First Name should not exceed 25 characters"),
    check("email")
        .trim()
        .notEmpty()
        .withMessage("Email is required")
        .isEmail()
        .withMessage("Invalid Email"),
    check("password")
        .trim()
        .notEmpty()
        .withMessage("Password is required")
        .isLength({ min: 6 })
        .withMessage("Password should be atleast 6 characters long"),
    check("phoneNumber1")
        .trim()
        .notEmpty()
        .withMessage("Phone Number is required")
        .matches(/^\+?[1-9]\d{1,14}$/)
        .withMessage("Invalid Phone Number"),


    (req, res, next) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            //If there are validation errors, return a 400 response with the error details
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }
        next();
    },

]

exports.validateForgetPassword = [
    check("email").trim().notEmpty().withMessage("Email is required").isEmail().withMessage("Please provide a valid email"),
    (req, res, next) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            //If there are validation errors, return a 400 response with the error details
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }
        next();
    }
]
exports.validateResetPassword = [
    check("password")
    .trim()
    .notEmpty()
    .withMessage("Password is required")
    .isLength({ min: 6 })
    .withMessage("Password should be atleast 6 characters long"),
    (req, res, next) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            //If there are validation errors, return a 400 response with the error details
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }
        next();
    }
]