var express = require('express');
var session = require('express-session');
var bodyParser = require('body-parser');
var path = require('path');
var crypto = require('crypto');
var mysql = require('mysql');

var app = express();

var currUserID = 100;
let serverUsername = "SERVER";

var server = app.listen(8080, function() { });

var io = require('socket.io').listen(server);

var socketToToken = new Map();
var userTokens = new Map();
var tokenUser = new Map();

io.on('connection', function(socket)
{
    console.log("User connected");

    let tempUsername = "user" + currUserID++;
    // socket.emit('send temp username', tempUsername);

    socket.on('disconnect', function(reason)
    {
        let leavingUser = tokenUser.get(socketToToken.get(socket));

        // We only care about users leaving which are logged in
        if(leavingUser != null) {
            console.log("User " + leavingUser + " left. Reason: " + reason);
            // Tell all clients that a user left so they can update their users online list
            io.emit('user left', leavingUser);
            // Send a message to the chat from the server declaring that someone left
            io.emit('new message', leavingUser + " has left the chat.", serverUsername);
            socketToToken.delete(socket);
        }
    });

    socket.on('new message', function(message, token)
    {
        if(String(userTokens.get(tokenUser.get(token))) !== String(token)) {
            // The token the client sent is invalid, they probably need to re-login
            socket.emit('invalid token');
            return;
        }

        console.log(tokenUser.get(token) + " said \"" + message + "\"");
        io.emit('new message', message, tokenUser.get(token));
    });

    socket.on('error', function(data)
    {
        console.log("There was an error: " + data);
    });

    // User tries to access chat
    socket.on('token login', function(token)
    {
        var user = tokenUser.get(token);
        if(user != null)
        {
            socket.emit('token login successful', user);
            socketToToken.set(socket, token);
            console.log(socketToToken.get(socket));
            for(let val of socketToToken.values()) {
                var curr = tokenUser.get(val);
                if(curr === user)
                    continue;
                socket.emit('user joined', curr);
                console.log("letting socket know that " + curr + " is in the chat.");
            }
            userLoggedIn(user);
        }
        else
        {
            socket.emit('token error');
        }
    });
});

var connection = mysql.createConnection({
    host     : 'localhost',
    user     : 'root',
    password : 'R3dF0rd5059',
    database: 'chatroom',
    insecureAuth: true
});

connection.connect(function(err)
{
    if (err) throw err;
    console.log("Connected!");
    // connection.query('SELECT * FROM chatroom_users;', '', function(error, results, fields) {

    // });
});

app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}));
app.use(bodyParser.urlencoded({extended : true}));
app.use(bodyParser.json());

app.use(express.static('chat room/static'));

app.post('/auth', function(request, response) {
    console.log("User trying to log in with username '" + request.body.username + "' and password '" + request.body.password + "'");

    var success = false;
    connection.query("SELECT * FROM chatroom_users WHERE username='" + request.body.username + "';", '', function(error, results, fields) {
        Object.keys(results).forEach(function(key) {
            var row = results[key];
            if(sha512(request.body.password, row.salt) === row.password_hash)
            {
                console.log("User " + request.body.username + " logged in");
                var token = getClientToken(request.body.username, row.salt);
                console.log("New token generated for '" + request.body.username + "': " + token);
                userTokens.set(request.body.username, token);
                tokenUser.set(token, request.body.username);
                console.log("This is the token for '" + request.body.username + "': " + userTokens.get(request.body.username));
                response.writeHead(200, { 'Content-Type': 'application/json' });
                var data =
                    {
                        "status":"success",
                        "token":"" + token
                    };
                response.write(JSON.stringify(data));
                response.end();
            }
            else
                sendIncorrectCredentials(response);
        });

        if(results.length === 0)
            sendIncorrectCredentials(response);
    });
});

function sendIncorrectCredentials(response) {
    console.log("incorrect credentials");
    response.writeHead(409, {'Content-Type': 'application/json'});
    response.write('{"status":"Username and/or password is incorrect."}');
    response.end();
}

app.post('/register', function(request, res)
{
    console.log("New user trying to register with username: " + request.body.username);

    var user = connection.query("SELECT * FROM chatroom_users WHERE username='" + request.body.username + "';", function(err, results)
    {
        // Check if user already exists
        if(results.length > 0) {
            console.log("Cannot register user " + request.body.username + " because that username is already taken.");
            res.writeHead(409, { 'Content-Type': 'application/json' });
            res.write('{"status":"That username is already taken, please try another.", "fields":["username"]}');
            res.end();
        }
        else
        {
            // Check if password fits within parameters
            if(request.body.password.length < 8)
            {
                res.writeHead(409, {'Content-Type': 'application/json'});
                res.write('{"status":"Password must be at least 8 characters long.", "fields":["password", "confirmPassword"]}');
                res.end();
                return;
            }

            // Success, register new user
            createNewUser(request.body.username, request.body.password);

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.write('{"status":"Registered"}');
            res.end();
        }
    });
});

function userLoggedIn(username)
{
    io.emit('user joined', username);
    io.emit('new message', username + " has joined the chat.", serverUsername);
}

function createNewUser(username, password)
{
    var salt = generateSalt(16);
    var hashedPass = sha512(password, salt);

    connection.query("INSERT INTO `chatroom_users`(username, password_hash, salt) VALUES('" + username
        + "','" + hashedPass + "','" + salt + "');");
}

var generateSalt = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
        .toString('hex') /** convert to hexadecimal format */
        .slice(0,length);   /** return required number of characters */
};

var sha512 = function(password, salt){
    var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    return value;
};

var getClientToken = function(username, pass, salt)
{
    return sha512(username + "", salt + "") + "." + generateSalt(64);
}