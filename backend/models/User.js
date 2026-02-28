const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: [true, "Please add a first name"],
        trim: true,
        maxLength: [25, "Full name cannot be more than 25 characters"]
    },
    lastName: {
        type: String,
        required: [true, "Please add a last name"],
        trim: true,
        maxLength: [25, "Full name cannot be more than 25 characters"]
    },
    email: {
        type: String,
        required: [true, "Please add a valid email"],
        unique: true,
        match: [
            /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/,
            "Please add a valid email"
        ],
    },
    password: {
        type: String,
        required: [true, "Please add a password"],
        minLength: [6, "Password must be at least 6 characters"],
        trim: true,
        select: false
    },
    phoneNumber1: {
        type: String,
        required: [true, "Please add a primary phone number"],
        validate: {
            validator: function (v) {
                //Skip validation if this is an OAuth user and phone not yet updated
                if (this.provider && this.phoneNumber1 === "Please update") {
                    return true
                }
                // Existing phone validation regex
                return /^\+?[\d\s-]+$/.test(v);
            },
            message: "Please add a valid phone number"
        }

    },
    provider: {
        type: String,
        enum: [null, "google", "facebook", "github"],
    },
    role: {
        type: String,
        enum: ["apprenant", "formateur", "admin"],
        default: "apprenant"
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: {
        type: String,
        select: false //hide from the query for security reason
    },
    verificationTokenExpire: { //Expiration time for the verification token (usually 24 hours)
        type: Date,
        select: false
    },
    resetPasswordToken: {
        type: String,
        select: false
    },
    resetPasswordExpire: { // token for reset password usually expire 1h
        type: Date,
        select: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    googleId: {
        type: String,
        unique: true,
        sparse: true// accepte null values
    },
    facebookId: {
        type: String,
        unique: true,
        sparse: true
    },
 
    profilePicture: {
        type: String,
        default: "default-avatar.png"
    },
    socialProvider: {
        type: String,
        enum: [null, "google", "facebook", ],
        //default : "local"
    },
    //For users who sign up with social providers
    isPasswordSet: {
        type: Boolean,
        default: false,
    },
    isProfileComplete: {
        type: Boolean,
        default: false
    },//force user to complete remplir info
   
    adminPrivileges: {
        canManageUsers: {
            type: Boolean,
            default: false
        },
        canManageCourses: {
            type: Boolean,
            default: false
        },
        canManageCategory: {
            type: Boolean,
            default: false
        },
        isSuperAdmin: {
            type: Boolean,
            default: false
        }
    }
})


// Encrypt password using bcrypt
userSchema.pre("save", async function (next) {
    if (this.password && this.isModified("password")) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        this.isPasswordSet = true;
    }
    // Set IsEmailValid to true for social login
    if (this.socialProvider) {
        this.isEmailVerified = true;
    }
    next();
})

userSchema.methods.linkSocialAccount = async function (provider, providerID) {
    this[`${provider}Id`] = providerID;
    this.socialProvider = provider;
    return this.save();
}

// Sign in JWT
userSchema.methods.getSignedJwtToken = function () {
    return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE
    })
}

//Compare / Match Password
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
}

//Refresh Token
userSchema.methods.getRefreshToken = function () {
    return jwt.sign({ id: this._id }, process.env.JWT_REFRESH_SECRET, {
        expiresIn: process.env.JWT_REFRESH_EXPIRE
    });
}
module.exports = mongoose.model("User", userSchema);

