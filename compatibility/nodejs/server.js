// Stolen from hawk examples

// Load modules

var Http = require('http');
var Request = require('request');
var Hawk = require('hawk');


// Declare internals

var internals = {
    credentials: {
        dh37fgj492je: {
            id: 'dh37fgj492je',                                             // Required by Hawk.client.header 
            key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            algorithm: 'sha256',
            user: 'Steve'
        }
    }
};


// Credentials lookup function

var credentialsFunc = function (id, callback) {

    return callback(null, internals.credentials[id]);
};


// Create HTTP server

var handler = function (req, res) {

    Hawk.server.authenticate(req, credentialsFunc, {}, function (err, credentials, artifacts) {

        var payload = (!err ? 'Hello ' + credentials.user + ' ' + artifacts.ext : 'Shoosh!');
        var serverAuth = Hawk.server.header(credentials, artifacts, { payload: payload, contentType: 'text/plain' });

        var headers = {
            'Content-Type': 'text/plain',
            'Server-Authorization': serverAuth
        };

        res.writeHead(!err ? 200 : 401, headers);
        res.end(payload);
    });
};

Http.createServer(handler).listen(8002, '127.0.0.1');
