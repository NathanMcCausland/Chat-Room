var express = require('express');

let connectedSockets = new Set();

var app = express();

var currUserID = 100;
let serverUsername = "SERVER";
let usersOnline = new Map();

var server = app.listen(8080, function()
{

});

var io = require('socket.io').listen(server);

io.on('connection', function(socket)
{
    console.log("User connected");

    let tempUsername = "user" + currUserID++;
    socket.emit('send temp username', tempUsername);
    usersOnline.set(socket, tempUsername);

    for(let val of usersOnline.values()) {
        if(val === tempUsername)
            continue;
        socket.emit('user joined', val);
    }

    io.emit('user joined', tempUsername);
    io.emit('new message', tempUsername + " has joined the chat.", serverUsername);

    socket.on('disconnect', function()
    {
        let leavingUser = usersOnline.get(socket);
        io.emit('user left', leavingUser);
        io.emit('new message', leavingUser + " has left the chat.", serverUsername);
        usersOnline.delete(socket);
        console.log("Another one bites the dust");
    });

    socket.on('new message', function(message, username)
    {
        console.log(username + " said \"" + message + "\"");
        io.emit('new message', message, username);
    });
});

app.use(express.static('chat room/static'));