var _ = require('lodash');
var io = require('socket.io-client');
//var log = require('../util/log');

var SocketStatus = {
    Disconnected: 0,
    Connected: 1,
    ConnectionFailed: 2,
    Connecting: 3
};

function PhysicalNetwork(){
    this.knownReceivers = {};
    this.sockets = {};
    this.notifyOnNextConnect = {};
    this.notifyOnNextDisconnect = {};
    this.registeredMiscCallbacks = {};
};

module.exports.singleton = function (){
    var instance = null;

    return {
        getInstance: function () {
            if (instance)
                return instance;
            return instance = new PhysicalNetwork();
        }
    };
}();

PhysicalNetwork.prototype._connected = function (url){
    return url in this.sockets && this.sockets[url].status === SocketStatus.Connected;
};

PhysicalNetwork.prototype._connecting = function (url){
    return url in this.sockets && this.sockets[url].status === SocketStatus.Connecting;
};

PhysicalNetwork.prototype._emitSingle = function (receiverId, event){
    if (!(receiverId in this.knownReceivers)){
        //log.debug('PhysicalNetwork._emitSingle(): Tried to emit to an unknown Async.');
        return;
    }
    var callbacks = this.knownReceivers[receiverId].callbacks;
    if (!(event in callbacks))
        return;
    var args = Array.prototype.slice.call(arguments, 2);
    callbacks[event].apply(null, args);
};

PhysicalNetwork.prototype._emitAll = function (event){
    for (var receiverId in this.knownReceivers)
        this._emitSingle.apply(this, [receiverId].concat(arguments));
};

PhysicalNetwork.prototype._notifyConnectionStatus = function (url, event){
    this._notifyConnectionStatus2(this.notifyOnNextConnect, url, event);
};

PhysicalNetwork.prototype._notifyConnectionStatus2 = function(obj, url, event){
    if (!(url in obj))
        return;
    var array = obj[url];
    var args = Array.prototype.slice.call(arguments, 3);
    for (var i in array)
        this._emitSingle.apply(this, [array[i], event].concat(args));
    delete obj[url];
};

function generateMiscEventHandler(self, eventName){
    return function (){
        self._emitAll.apply(self, [eventName].concat(arguments));
    };
};

PhysicalNetwork.prototype._addMiscCallback = function (eventName){
    if (eventName == 'connect')
        return false;
    if (eventName == 'connect_error')
        return false;
    if (eventName == 'disconnect')
        return false;
    if (eventName == 'message')
        return false;
    if (eventName in this.registeredMiscCallbacks)
        return false;
    this.registeredMiscCallbacks[eventName] = null;
    return true;
};

PhysicalNetwork.prototype._addAllMiscCallbacks = function (){
    for (var receiverId in this.knownReceivers){
        var receiver = this.knownReceivers[receiverId];
        for (var eventName in receiver.callbacks)
            this._addMiscCallback(eventName);
    }
};

PhysicalNetwork.prototype._registerMiscCallbacksInBatch = function (socket){
    for (var eventName in this.registeredMiscCallbacks){
        socket.on(
            eventName,
            generateMiscEventHandler(this, eventName)
        );
    }
};

PhysicalNetwork.prototype._onMessage = function(to, message, payload){
    var receiver = this.knownReceivers[to];
    if (!receiver)
        return;
    
    var cb = receiver.callbacks[message];
    if (!cb)
        return;
    
    cb(payload);
}

PhysicalNetwork.prototype.startNetwork = function (receiverId, url, options){
    this.knownReceivers[receiverId].url = url;
    if (this._connected(url)){
        this._emitSingle(receiverId, 'connect');
        return;
    }
    
    if (!(url in this.notifyOnNextConnect))
        this.notifyOnNextConnect[url] = [];
    this.notifyOnNextConnect[url].push(receiverId);

    if (this._connecting(url)){
        return;
    }
    
    var socket = io.connect(url, options);
    this.sockets[url] = {
        socket: socket,
        status: SocketStatus.Connecting
    };
    var self = this;
    socket.on(
        'connect',
        function (){
            self.sockets[url].status = SocketStatus.Connected;
            self.notifyOnNextDisconnect[url] = _.clone(self.notifyOnNextConnect[url]);
            socket.on(
                'disconnect',
                function(){
                    self.sockets[url] = {
                        status: SocketStatus.Disconnected
                    };
                    self._notifyConnectionStatus2(self.notifyOnNextDisconnect, url, 'disconnect');
                }
            );
            self._notifyConnectionStatus(url, 'connect');
        }
    );
    socket.on(
        'connect_error',
        function (){
            self.sockets[url] = {
                status: SocketStatus.ConnectionFailed
            };
            self._notifyConnectionStatus.apply(self, [url, 'connect_error'].concat(arguments));
        }
    );
    socket.on(
        'message',
        function (data){
            self._onMessage(data.to, data.message, data.payload);
        }
    );
    socket.on(
        'multimessage',
        function (data){
            for (var i in data.to)
                self._onMessage(data.to[i], data.message, data.payload);
        }
    );
    self._addAllMiscCallbacks();
    self._registerMiscCallbacksInBatch(socket);
};

PhysicalNetwork.prototype.registerReceiver = function (receiverId, callbackMap){
    this.knownReceivers[receiverId] = {
        callbacks: _.clone(callbackMap)
    };
};

PhysicalNetwork.prototype.registerReceiverCallback = function (receiverId, event, newCallback){
    var map = null;
    if (!(receiverId in this.knownReceivers))
        this.knownReceivers[receiverId] = {};
    this.knownReceivers[receiverId][event] = newCallback;
    if (!this._addMiscCallback(event))
        return;
    for (var url in this.sockets)
        this.sockets[url].socket.on(event, generateMiscEventHandler(event));
};

PhysicalNetwork.prototype._socketFromReceiverId = function(receiverId){
    //var f = log.debug.bind(log);
    var f = function(){};
    if (!(receiverId in this.knownReceivers)){
        f('PhysicalNetwork._socketFromReceiverId(): An unknown Async tried to send data.');
        return null;
    }
    var async = this.knownReceivers[receiverId];
    if (!('url' in async)){
        f('PhysicalNetwork._socketFromReceiverId(): An Async tried to send data before calling startNetwork().');
        f(async);
        return null;
    }
    var url = async.url;
    if (!this._connected(url)){
        f('PhysicalNetwork._socketFromReceiverId(): The socket is not yet ready.');
        return null;
    }
    return this.sockets[url].socket;
}

PhysicalNetwork.prototype.send = function (receiverId, event, payload){
    var socket = this._socketFromReceiverId(receiverId);
    if (!socket)
        return;
    
    socket.emit(event, {from: receiverId, payload: (payload || null)});
}

PhysicalNetwork.prototype.cleanUp = function (receiverId){
    var async = this.knownReceivers[receiverId];
    if (!async)
        return;
    delete this.knownReceivers[receiverId];
    var url = async.url;
    if (!url || !this._connected(url))
        return;
    var any = false;
    for (var a in this.knownReceivers){
        if (a.url === url){
            any = true;
            break;
        }
    }
    if (any)
        return;
    var socket = this.sockets[url];
    socket.disconnect();
    socket.removeAllListeners();
    delete this.sockets[url];
}

PhysicalNetwork.prototype.isConnected = function(receiverId){
    if (!(receiverId in this.knownReceivers))
        return false;
    var async = this.knownReceivers[receiverId];
    if (!(url in async))
        return false;
    return this._connected(async.url);
}
