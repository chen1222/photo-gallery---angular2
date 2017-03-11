var express = require('express'),
    router = express.Router(),
    mongoose = require('mongoose'),
    nev = require('email-verification')(mongoose);
var global = require('../global/config');
var accountSchema = require('../model/model').accountSchema;
var accountModel = mongoose.model('Account', accountSchema);
var bCrypt = require('bcrypt-nodejs');
var Util = require('../lib/util');
var async = require('async');
var crypto = require('crypto');
var bCrypt = require('bcrypt-nodejs');
var nodemailer = require('nodemailer');

// sync version of hash ing function 
var myHasher = function (password, tempUserData, insertTempUser, callback) {
    var hash = bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
    return insertTempUser(hash, tempUserData, callback);
};
var errorHandler = function (res, err, msg) {
    console.log('Error', err, msg);
    Util.responseHandler(res, false, msg, null);
}

module.exports = function (passport) {
    //log in
    router.post('/login', (req, res, next) => {
        passport.authenticate('login', (err, user, info) => {
            if (err) { res.status(500).send({ success: false, message: 'Server Authentication Error...' }); return next(err); }
            if (!user) { console.log('aaa'); res.send({ success: false, message: 'Invalid username or password...' }); return next(err); }
            req.login(user, loginErr => {
                if (loginErr) {
                    return next(loginErr);
                }
                return res.send({ success: true, message: 'Successfully logged in...', data: { user: user } });
            });
        })(req, res, next);
    });

    //sign up
    router.post('/signup', (req, res, next) => {
        username = req.body.username;
        accountModel.findOne({ 'username': username }, function (err, account) {
            if (err) {
                console.log('Error in SignUp: ' + err);
                return Util.responseHandler(res, false, 'Error', null);
            }
            if (account) {
                return Util.responseHandler(res, false, `User already exists with username ${username}`, null);
            } else {
                accountModel.insertMany([{
                    username: req.body.username,
                    password: createHash(req.body.password),
                    firstname: req.body.firstname,
                    secondname: req.body.lastname
                }]).then((doc) => {
                    return Util.responseHandler(res, true, 'Success', null);
                })
            }
        });
    });

    var createHash = function (password) {
        return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
    };
    return router;
}