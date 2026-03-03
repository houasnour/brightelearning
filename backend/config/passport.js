const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const User = require("../models/User");
const crypto = require("crypto");

/*
|--------------------------------------------------------------------------
| Helper Function: Find or Create User
|--------------------------------------------------------------------------
*/
const findOrCreateUser = async ({
  firstName,
  lastName,
  email,
  provider,
  providerId,
}) => {
  let user = await User.findOne({ email });

  if (!user) {
    const randomPassword = crypto.randomBytes(32).toString("hex");

    user = await User.create({
      firstName,
      lastName,
      email,
      password: randomPassword,
      phoneNumber1: "Please update",
      isEmailVerified: true,
      provider,
      providerId,
      isProfileComplete: false,
    });
  }

  return user;
};

/*
|--------------------------------------------------------------------------
| GOOGLE STRATEGY
|--------------------------------------------------------------------------
*/
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL, // mieux que hardcoded
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;

        if (!email) {
          return done(new Error("Google account has no email"), null);
        }

        const user = await findOrCreateUser({
          firstName: profile.name?.givenName,
          lastName: profile.name?.familyName,
          email,
          provider: "google",
          providerId: profile.id,
        });

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

/*
|--------------------------------------------------------------------------
| FACEBOOK STRATEGY
|--------------------------------------------------------------------------
*/
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL, // mieux que hardcoded
      profileFields: ["id", "emails", "name", "photos"],
      enableProof: true,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;

        if (!email) {
          return done(new Error("Facebook account has no email"), null);
        }

        const user = await findOrCreateUser({
          firstName: profile.name?.givenName,
          lastName: profile.name?.familyName,
          email,
          provider: "facebook",
          providerId: profile.id,
        });

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

module.exports = passport;