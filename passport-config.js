const localStratgegy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

function initialize(passport, getUserByEmail, getUserById) {
    const authenticate = async (email, password, done) => {
        const user = getUserByEmail(email);
        if (user == null) {
            return done(null, false, { message: 'No user with this email'});
        }
        try {
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user);
            } else {
                return done(null, false, {message: 'incorrect password'});
            }
        } catch(e) {
            return done(e);
        }
    };
    passport.use(new localStratgegy({ usernameField: 'email'}, authenticate));
    passport.serializeUser((user, done) => {
        done(null, user.id)
    });
    passport.deserializeUser((id, done) => {
        return done(null, getUserById(id))
    });
}

module.exports = initialize;