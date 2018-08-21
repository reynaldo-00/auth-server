const jwt = require('jwt-simple');
const config = require('../config');
const User = require('../models/user');

const tokenForUser = (user) => {
    const timestamp = new Date().getTime();
    return jwt.encode({ sub: user.id, iat: timestamp }, config.secrete)
};

exports.signup = (req, res, next) => {
    console.log(req.body);

    const email = req.body.email;
    const password = req.body.password;

    if ( !email || !password ) { 
        return res.status(422).send({ error: "Email AND Password required"})
    }

    // See if email already exist
    User.findOne({ email }, (err, exist) => {
        if (err) { return next(err) }

        // If user with email does exist, return error
        if (exist) { return res.status(422).send({ error: "Email is in use"}) }

        // If a user with email does NOT exist, create and save user record
        const newUser = new User({ email, password });
        newUser.save((err) => {
            if (err) { return next(err) }

            // Respond to request 
            res.json({ token: tokenForUser(newUser)});
        });
    });
}

exports.signin = (req, res, next) => {
    // User has been authenticated
    // Return Token
    res.send({token: tokenForUser(req.user)});
}