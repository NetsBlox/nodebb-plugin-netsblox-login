var passport = module.parent.require('passport'),
    winston = module.parent.require('winston'),
    user = module.parent.require('./user'),
    passportLocal = module.parent.require('passport-local').Strategy,
    hash = require('./libs/sha512').hex_sha512,
    url = (process.env.NETSBLOX_URL || 'https://editor.netsblox.org') + '/api',
    request = require('request'),
    COOKIE_ID = 'netsblox-cookie',
    plugin = {};

plugin.login = function() {
    winston.info('[login] Registering new local login strategy');
    passport.use(new passportLocal({passReqToCallback: true}, plugin.continueLogin));
};

plugin.continueLogin = function(req, username, password, next) {
    var jar = request.jar();
    // POST request to url
    winston.info('[login] Trying to log in at ' + url);
    request.post({
        url: url,
        jar: jar,
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

            if (res.statusCode === 200) {
                // Parse the user response
                try {
                    body = JSON.parse(body);
                } catch (err) {
                    return next(new Error('[[error:' + err + ']]'));
                }

                var cookie = jar.getCookies(url).find(function(c) {
                    return c.key === COOKIE_ID;
                });
                
                // Attach the netsblox cookie to the user's response
                if (cookie) {
                    const rawValue = cookie.toString();

                    winston.info(`[login] forwarding "${COOKIE_ID}" cookie`);
                    req.res.set('Set-Cookie', rawValue);
                }
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

            } else if (399 < res.statusCode < 500) {
                // But if the login was unsuccessful, pass an error back, like so:
                let reason = 'Invalid Username or Password';
                const resMsg = res.body.toLowerCase();

                if (resMsg.includes('password')) {
                    reason = 'invalid-password';
                } else if (resMsg.includes('user')) {
                    reason = 'invalid-username';
                }
                next(new Error(`[[error:${reason}]]`));
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

// Registration
plugin.validate = function(data, callback) {
    var username = data.userData.username,
        email = data.userData.email,
        password = data.userData.password,
        signupUrl = url + '/SignUp/validate';

    // Don't login on registration
    data.res.locals.processLogin = false;

    // Try to SignUp on NetsBlox
    winston.info('[registration] Validating at ' + url);
    request.post({
        url: signupUrl,
        form: {
            Username: username,
            Password: hash(password),
            Email: email
        }},
        (err, res, body) => {
            if (err) {
                return callback(err);
            }

            if (res.statusCode === 200) {  // success!
                return callback();
            } else {
                return callback(new Error(body));
            }
        });
};

plugin.checkAndRegister = function(data, callback) {
    plugin.register(data.userData, function(err) {
        if (err) {
            return callback(err);
        }
        plugin.continueLogin(
            data,
            data.userData.username,
            data.userData.password,
            callback
        );
    });
};

plugin.registerOnComplete = function(data, callback) {
    var uid = data.uid;

    user.getUsersFields([uid], ['username', 'email'], function(err, users) {
        if (err) {
            return callback(err);
        }
        return plugin.register(users.pop(), callback);
    });
};

plugin.register = function(userData, callback) {
    var signupUrl = url + '/SignUp';
        username = userData.username,
        email = userData.email,
        password = userData.password;

    // Try to SignUp on NetsBlox
    winston.info('[registration] Signing up at NetsBlox...');
    request.post({
        url: signupUrl,
        form: {
            Username: username,
            Password: password ? hash(password) : '',
            Email: email
        }},
        function(err, res, body) {
            if (err) {
                return callback(err);
            }

            if (res.statusCode === 200) {  // success!
                return callback();
            } else {
                return callback(new Error(body));
            }
        });
};

// logout
plugin.logout = function(data, callback) {
    var jar = request.jar(),
        cookie = data.req.cookies[COOKIE_ID];

    winston.info('[logout] using cookie ' + cookie);
    jar.setCookie(cookie, url, function(err, cookie) {
        if (err) {
            winston.warn('[logout] Could not set cookie: ' + err.toString());
        }
        winston.info('[logout] logging out from ' + url);
        request.get({
            url: url + '/logout',
        }, function(err, res, body) {
            if (err) {
                return callback(err);
            }
            if (res.statusCode === 200) {
                // delete the cookie for good measure
                winston.info('[logout] clearing netsblox cookie');
                data.res.clearCookie(COOKIE_ID);
                return callback();
            } else {
                return callback(body);
            }
        });
    });
};

module.exports = plugin;
