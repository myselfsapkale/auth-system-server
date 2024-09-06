import passport from "passport";
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';


passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID as string,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
    callbackURL: process.env.GOOGLE_CALLBACK_URL as string,
    scope: ['profile', 'email', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
    state: false,
    passReqToCallback: true
},
    function verify(req, accessToken, refreshToken, profile, cb) {
        if (!accessToken || !Object.keys(profile)) return cb(true);
        let user = {
            user_first_name: profile?.name?.givenName,
            user_type: "user",
            user_last_name: profile?.name?.familyName,
            user_email: profile?.emails![0]?.value,
            provider: profile.provider,
            is_sso: 1,
            is_active: 1
        };
        cb(null, user);
    }
));


export { passport };