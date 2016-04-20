var passport = module.parent.require('passport'),
    winston = module.parent.require('winston'),
    passportLocal = module.parent.require('passport-local').Strategy,
    hash = require('./libs/sha512').hex_sha512,
    url = 'http://editor.netsblox.org/api',
    request = require('request'),
    plugin = {};

plugin.login = function() {
    winston.info('[login] Registering new local login strategy');
    passport.use(new passportLocal({passReqToCallback: true}, plugin.continueLogin));
};

plugin.continueLogin = function(req, username, password, next) {
    // POST request to url
    request.post({
        url: url,
        form: {
            __u: username,
            __h: hash(password),
            return_user: true
        }},
        (err, res, body) => {
            if (err) {
                winston.error(err);
                return next(new Error('[[error:' + err + ']]'));
            }

            // Parse the user response
            try {
                body = JSON.parse(body);
            } catch (err) {
                return next(new Error('[[error:' + err + ']]'));
            }

            if (res.statusCode === 200) {
                var user = module.parent.require('./user');
                
                user.getUidByEmail(body.email, (err, uid) => {
                    user.exists(uid, (err, exists) => {
                        winston.info(`[login] username "${username}" exists: ${exists}`);
                        if (err) {
                            winston.error('Could not check if user exists...');
                            return next(new Error('[[error:' + err + ']]'));
                        }

                        if (!exists) {
                            winston.info(`[login] Creating ${username} ${body.admin ? '(admin)': ''}`);
                            user.create({
                                username: username,
                                isAdmin: body.admin,
                                displayName: username,
                                email: body.email
                            }, (err, uid) => {
                                if (err) {
                                    return next(new Error(err));
                                }
                
                                // If the login was successful:
                                next(null, {
                                    uid: uid
                                }, '[[success:authentication-successful]]');

                            });
                        } else {
                            user.getUidByEmail(body.email, (err, uid) => {
                                if (err) {
                                    return next(new Error(err));
                                }

                                // If the login was successful:
                                next(null, {
                                    uid: uid
                                }, '[[success:authentication-successful]]');
                            })
                        }
                    });
                });

            } else if (res.statusCode === 404) {
                // But if the login was unsuccessful, pass an error back, like so:
                next(new Error('[[error:invalid-username-or-password]]'));
            }
        });

    
    /*
        You'll probably want to add login in this method to determine whether a login
        refers to an existing user (in which case log in as above), or a new user, in
        which case you'd want to create the user by calling User.create. For your
        convenience, this is how you'd create a user:
      
        var user = module.parent.require('./user');
        
        user.create({
            username: 'someuser',
            email: 'someuser@example.com'
        });
        
        Acceptable values are: username, email, password
    */
};

module.exports = plugin;
