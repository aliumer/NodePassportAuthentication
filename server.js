if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
    // this is going to load all our environment variables and set them in process.env
}
const express = require('express');
const app = express();
const flash = require('express-flash');
const session = require('express-session');
const bcrypt = require('bcrypt');
const passport = require('passport');
const initializePassport = require('./passport-config');
const methodOverride = require('method-override');

initializePassport(
    passport,
    email => users.find(u => u.email === email),
    id => users.find(u => u.id === id)
)

const users = [];

app.set('view-engine', 'ejs');

// telling express we want to read values from forms in our request handlers.
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

app.get('/', isAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name });
})

app.get('/login', (req, res) => {
    res.render('login.ejs');
})

app.post('/login'
    ,checkNotAuthenticated
    ,passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/login',
        failureFlash: true
    }));

app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs');
})

app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        });
        res.redirect('/login');
    } catch {
        res.status(401).send();
    }
})

app.delete('/logout', (req, res) => {
    // since we can't call delete from html
    // delete is not supported by the html forms. forms can only do post
    // so to be able to call delete we need another library called method-override  
    req.logout();
    res.redirect('/login');
})

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    } else {
        res.redirect('/login');
    }
}

function checkNotAuthenticated(req, res, next) {
    // if they are already authenticated
    if (req.isAuthenticated()) {
        return res.redirect('/');
    } else {
        next();
    }
}

app.listen(3000);