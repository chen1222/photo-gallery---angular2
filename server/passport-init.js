var accountSchema = require('./model/model').accountSchema;
var mongoose = require('mongoose');
var Account = mongoose.model('Account', accountSchema);
var LocalStrategy = require('passport-local').Strategy;
var bCrypt = require('bcrypt-nodejs');
var Util = require('./lib/util.js');


module.exports = function (passport) {

	// Passport needs to be able to serialize and deserialize users to support persistent login sessions
	passport.serializeUser(function (account, done) {
		console.log('serializing user:', account.username);
		done(null, account._id);
	});

	passport.deserializeUser(function (id, done) {
		Account.findById(id, function (err, account) {
			console.log('deserializing user:', account.username);
			done(err, account);
		});
	});

	passport.use('login', new LocalStrategy({
			passReqToCallback : true
		},
		function(req, username, password, done) { 
			// check in mongo if a user with username exists or not
			Account.findOne({ 'username' :  username }, 
				function(err, user) {
					if (err)
						return done(err);
					if (!user){
						console.log('User Not Found with username '+username);
						return done(null, false);                 
					}
					if (!isValidPassword(user, password)){
						console.log('Invalid Password');
						return done(null, false); // redirect back to login page
					}
					return done(null, user);
				}
			);
		}
	));

	passport.use('signup', new LocalStrategy({
		passReqToCallback: true // allows us to pass back the entire request to the callback
	},
		function (req, username, password, done) {
			Account.findOne({ 'username': username }, function (err, account) {
				if (err) {
					console.log('Error in SignUp: ' + err);
					return done(err);
				}
				if (account) {
					return done(null, false, { message: `User already exists with username ${username}` });
				} else {
					Account.insertMany([{
						username: req.body.username,
						password: req.body.password,
						firstname: req.body.firstname,
						secondname: req.body.lastname
					}]).then((doc) => {
						return done(null, doc[0]);
					})
				}
			});
		})
	);


	var isValidPassword = function (account, password) {
		return bCrypt.compareSync(password, account.password);
	};
	// Generates hash using bCrypt
	var createHash = function (password) {
		return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
	};
};