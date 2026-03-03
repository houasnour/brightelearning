const mongoose = require("mongoose");
const UserActivitySchema = new mongoose.Schema({
    user : {
        type : mongoose.Schema.ObjectId,
        ref : "User",
        required : true
    },
    action : {
        type : String,
        required : true,
        enum : ["REGISTER","LOGIN","LOGOUT","EMAIL_VERIFICATION","TOKEN_REFRESH","EMAIL_VERIFIED","PASSWORD_RESET"]
    },
    deviceInfo:{
        browser : {
            name : String,
            version : String
        },
    os : {
        name : String,
        version : String
    },
    device: {
        type : String, //Mobile, Desktop, Tablet
        brand : String,
    },
    isMobile : Boolean,
    isDesktop : Boolean,
    isTablet : Boolean
    },
    location : {
        ip : String,
        city : String,
        country : String,
        timezone : String,
    },
    sessionData : {
        userAgent : String,
        timestamp : {
            type : Date,
            default : Date.now
        },
        duration : Number, //in seconds
    },
    status : {
        type : String,
        enum : ["SUCCESS","FAILED","PENDING"],
        required : true
    },
    details : String,
},
{timestamps : true}
);

UserActivitySchema.index({user : 1 , 'sessionData.timestamp' : -1});
UserActivitySchema.index({"deviceInfo.device.type" : 1 });
UserActivitySchema.index({action : 1});
module.exports = mongoose.model("UserActivity",UserActivitySchema);