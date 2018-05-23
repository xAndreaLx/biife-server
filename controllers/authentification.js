const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret); // sub properties is a jwt convention for the 'subject' of the token ||iat is for issued at time
}

exports.signin = (req, res, next) => {
  // User has already had their email and password auth'd
  // We just need to give them a token
  // we can access to the user model by req.user thx to the end of our callback function in our local strategy when we call done with the user
  // passport assign this user to the request
  res.send({ token: tokenForUser(req.user)});
}

exports.signup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  // See if a user with the given email exists
  User.findOne({ email: email }, (err, existingUser) => {
    if (err) return next(err);

    if (!email || !password) {
      return res.status(422).send({ error: 'Email and password needed' });
    }

    // if a user with email does exist, return an error
    if (existingUser) {
      return res.status(422).send({ error: 'Email is in use' });
    }

    // if a user with email does NOT exist, create and save user record
    const user = new User({
      email: email,
      password: password
    });

    user.save(err => {
      if (err) return next(err);
    });

    // repond to request indicating the user was created
    res.json({ token: tokenForUser(user) });
  });
};
