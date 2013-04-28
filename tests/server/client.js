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

// Send unauthenticated request
unAuthDone = false;
Request('http://127.0.0.1:8002/resource/1?b=1&a=2', function (error, response, body) {
    unAuthDone = true;
    if (error) console.error(error);
    if (response && response.statusCode) {
        console.log('Unauthenticated request was');
        console.log(response.statusCode + ': ' + body);
    }
    if (authDone && unAuthDone) process.exit(0);
});


// Send authenticated request
var authDone = false;
credentialsFunc('dh37fgj492je', function (err, credentials) {

    var header = Hawk.client.header('http://127.0.0.1:8002/resource/1?b=1&a=2', 'GET', { credentials: credentials, ext: 'and welcome!' });
    var options = {
        uri: 'http://127.0.0.1:8002/resource/1?b=1&a=2',
        method: 'GET',
        headers: {
            authorization: header.field
        }
    };

    Request(options, function (error, response, body) {
	authDone = true;
        var isValid = Hawk.client.authenticate(response, credentials, header.artifacts, { payload: body });
	console.log('authenticated request was:');
	if (error) console.error(error);
        if (response && response.statusCode) {
            console.log(response.statusCode + ': ' + body + (isValid ? ' (valid)' : ' (invalid)'));
	}
        if (authDone && unAuthDone) process.exit(0);
    });
});

