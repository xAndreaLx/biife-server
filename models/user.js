const mongoose = require('mongoose');
const Schema = require('mongoose').Schema;
const bcrypt = require('bcrypt-nodejs');

// Define our model
const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true },
  password: String
});

// On save Hook, encrypt password
// before saving a model, run this function ( with .pre())
userSchema.pre('save', function(next) {
  // get access to the user model
  const user = this;

  console.log("test");
  // generate a salt then run callback
  bcrypt.genSalt(10, (err, salt) => {
    if (err) return next(err);

    // hash our password using the salt
    bcrypt.hash(user.password, salt, null, (err, hash) => {
      if (err) return next(err);

      // overwrite plain text password with encrypted password
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) { return callback(err);}
    
    callback(null, isMatch);
  })
}

// Create the model Class
const ModelClass = mongoose.model('user', userSchema);

// Export the model
module.exports = ModelClass;
