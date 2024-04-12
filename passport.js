const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./user');
const bcrypt = require('bcrypt');
const flash = require('connect-flash');

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async function(email, password, done) {
    try {
        const user = await User.findOne({ email: email });
        if (!user) {
            return done(null, false, { message: 'Incorrect email or password.' });
        }

        // Compare hashed passwords
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return done(null, false, { message: 'Incorrect email or password.' });
        }

        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

module.exports = passport;
