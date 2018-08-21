const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Local Strategy
const localOptions = { usernameField: 'email'};
const localLogin = new LocalStrategy(localOptions, (email, password, done) => {
    // Verify user with email and password
    // If it is correct call done with user object
    // If it is not correct call done with false
    User.findOne({email}, (err, user) => {
        if (err) { return done(err) }
        if (!user) { return done(null, false) }

        user.comparePassword(password, (err, isMatch) => {
            if (err) { return done(err) };
            if (!isMatch) { return done(null, false) };

            return done(null, user);
        });

    })

});

// Configure options for JWT Passport
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secrete,
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {
    // See if user ID in the payload exist in DB
    // If it dose call done with that user object
    // If it does not call done without user object

    User.findById(payload.sub, (err, user) => {
        if (err) { return done(err, false)};

        if (user) {
            done(null, user);
        } else {
            done(null, false);
        }
    })

});

// Tell Passport to use JWT strategy

passport.use(jwtLogin);
passport.use(localLogin);
