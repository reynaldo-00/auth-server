const mongoose = require('mongoose');
const bcrypt = require('bcrypt-nodejs');
const Schema = mongoose.Schema;

//Define Model
const userSchema = new Schema({
    email: { type: String, unique: true, uppercase: true },
    password: String
})

// On Save Hook, Encrypt Password
// Before saving a model run this function
userSchema.pre('save', function(next) {
    // get access to user model
    const user = this; // user.email user.password

    // Generate a salt
    bcrypt.genSalt(10, (err, salt) => {
        if (err) { return next(err) }
        
        // hash(encrypt) password using salt
        bcrypt.hash(user.password, salt, null, (err, hash) => {
            if (err) { return next(err) }
            
            // override plain text password with encrypted password
            user.password = hash;
            next();
        })
    })
})

userSchema.methods.comparePassword = function (candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
        if (err) { return callback(err) };
        
        callback(null, isMatch);
    })
};

// Create Model Class
const ModelClass = mongoose.model('user', userSchema);

//Export Model
module.exports = ModelClass;
