var $ = require('preconditions').singleton();
var _ = require('lodash');

var Bitcore = require('bitcore-lib');
var BitcorePayPro = require('bitcore-payment-protocol');
var PayPro = {};

PayPro._nodeRequest = function(opts, cb) {
  opts.agent = false;
  var http = opts.httpNode || (opts.proto === 'http' ? require('http') : require('https'));

  var fn = 'get';

  if (opts.method && opts.method.toUpperCase() !== 'GET') {
    fn = 'request';
  }

  var req = http[fn](opts, function(res) {
    var data = []; // List of Buffer objects
    res.on('data', function(chunk) {
      data.push(chunk); // Append Buffer object
    });
    res.on('end', function() {
      data = Buffer.concat(data); // Make one large Buffer of it
      if (res.statusCode !== 200) {
        if (data && data.length) {
          return cb(new Error('Error making payment request: ' + data.toString()));
        }
        else {
          return cb(new Error('HTTP Request Error'));
        }
      }
      return cb(null, data, res.headers);
    });
  });

  req.end();
};

PayPro._browserRequest = function(opts, cb) {
  var method = (opts.method || 'GET').toUpperCase();
  var url = opts.url;
  var req = opts;

  req.headers = req.headers || {};
  req.body = req.body || req.data || '';

  var xhr = opts.xhr || new XMLHttpRequest();
  xhr.open(method, url, true);

  Object.keys(req.headers).forEach(function(key) {
    var val = req.headers[key];
    if (key === 'Content-Length') return;
    if (key === 'Content-Transfer-Encoding') return;
    xhr.setRequestHeader(key, val);
  });
  xhr.responseType = 'arraybuffer';

  xhr.onload = function(event) {
    var response = new Uint8Array(xhr.response);
    var headers = {};
    var rawHeaders = xhr.getAllResponseHeaders();
    rawHeaders.trim().split(/[\r\n]+/).forEach(function (line) {
      var parts = line.split(': ');
      var header = parts.shift();
      headers[header] = parts.join(': ');
    });
    if (xhr.status !== 200) {
      try {
        var responseString = String.fromCharCode.apply(null, response);
        return cb(new Error(responseString));
      }
      catch(e) {
        return cb(new Error(xhr.statusText));
      }
    }
    return cb(null, response, headers);
  };

  xhr.onerror = function(event) {
    var status;
    if (xhr.status === 0 || !xhr.statusText) {
      status = 'HTTP Request Error';
    } else {
      status = xhr.statusText;
    }
    return cb(new Error(status));
  };

  if (req.body) {
    xhr.send(req.body);
  } else {
    xhr.send(null);
  }
};

var getHttp = function(opts) {
  var match = opts.url.match(/^((http[s]?):\/)?\/?([^:\/\s]+)(:(\d{3,5}))?((\/\w+)*\/)([\w\-\.]+[^#?\s]+)(.*)?(#[\w\-]+)?$/);

  opts.proto = match[2];
  opts.host = match[3];
  opts.port = match[5] || undefined;
  opts.path = match[6] + match[8];

  if (opts.http) {
    return opts.http;
  }

  var env = opts.env;
  if (!env)
    env = (process && !process.browser) ? 'node' : 'browser';

  return (env === 'node') ? PayPro._nodeRequest : PayPro._browserRequest;
};

PayPro._checkIfJsonIsSupported = function (opts, cb) {
  var http = getHttp(opts);
  var options = _.merge({}, opts, {
    method: 'OPTIONS'
  });

  http(options, function (err, response, headers) {
    if (err) {
      return cb(err);
    }
    if (typeof headers.accept === 'string' && headers.accept.indexOf('application/payment-request') !== -1) {
      return cb(null, true);
    }
    else {
      return cb(null, false);
    }
  });
};

PayPro.get = function(opts, cb) {
  $.checkArgument(opts && opts.url);

  PayPro._checkIfJsonIsSupported(opts, function (err, jsonSupported) {
    if (err) {
      return cb(err);
    }
    if (jsonSupported) {
      PayPro._getJsonPaymentRequest(opts, cb);
    }
    else {
      PayPro._getLegacyPaymentRequest(opts, cb);
    }
  });
};

PayPro._getJsonPaymentRequest = function (opts, cb) {
  var http = getHttp(opts);

  opts.headers = opts.headers || {
    'Accept': BitcorePayPro.JSON_PAYMENT_REQUEST_CONTENT_TYPE
  };

  http(opts, function (err, dataBuffer) {
    var body;

    if (err) {
      return cb(err);
    }

    try {
      var buffer = String.fromCharCode.apply(null, dataBuffer);
      body = JSON.parse(buffer);
    }
    catch (e) {
      return cb(new Error('Could not parse payment protocol: ' + e));
    }

    return cb(null, {
      format: 'json',
      //These are implied if its a successful HTTPS request, however actual signatures are still WIP
      verified: opts.proto === 'https',
      caTrusted: opts.proto === 'https',
      expires: new Date(body.expires),
      memo: body.memo,
      time: new Date(body.time),
      merchant_data: {
        invoiceId: body.paymentId
      },
      currency: body.currency,
      toAddress: body.outputs[0].address,
      amount: body.outputs[0].amount,
      domain: opts.host,
      url: body.paymentUrl
    });
  });
};

PayPro._getLegacyPaymentRequest = function (opts, cb) {
  var http = getHttp(opts);

  opts.headers = opts.headers || {
    'Accept': BitcorePayPro.LEGACY_PAYMENT[opts.currency].REQUEST_CONTENT_TYPE,
    'Content-Type': 'application/octet-stream'
  };

  http(opts, function(err, dataBuffer) {
    if (err) return cb(err);
    var request, verified, signature, serializedDetails;
    try {
      var body = BitcorePayPro.PaymentRequest.decode(dataBuffer);
      request = (new BitcorePayPro()).makePaymentRequest(body);
      signature = request.get('signature');
      serializedDetails = request.get('serialized_payment_details');
      // Verify the signature
      verified = request.verify(true);
    } catch (e) {
      return cb(new Error('Could not parse payment protocol: ' + e));
    }

    // Get the payment details
    var decodedDetails = BitcorePayPro.PaymentDetails.decode(serializedDetails);
    var pd = new BitcorePayPro();
    pd = pd.makePaymentDetails(decodedDetails);

    var outputs = pd.get('outputs');
    if (outputs.length > 1)
      return cb(new Error('Payment Protocol Error: Requests with more that one output are not supported'))

    var output = outputs[0];

    var amount = output.get('amount').toNumber();
    var network = pd.get('network') === 'test' ? 'testnet' : 'livenet';

    // We love payment protocol
    var offset = output.get('script').offset;
    var limit = output.get('script').limit;

    // NOTE: For some reason output.script.buffer
    // is only an ArrayBuffer
    var buffer = new Buffer(new Uint8Array(output.get('script').buffer));
    var scriptBuf = buffer.slice(offset, limit);
    var addr = new Bitcore.Address.fromScript(new Bitcore.Script(scriptBuf), network);

    var md = pd.get('merchant_data');

    if (md) {
      md = md.toString();
    }

    var ok = verified.verified;
    var caName;

    if (verified.isChain) {
      ok = ok && verified.chainVerified;
    }

    return cb(null, {
      verified: ok,
      caTrusted: verified.caTrusted,
      caName: verified.caName,
      selfSigned: verified.selfSigned,
      expires: new Date(pd.get('expires') * 1000),
      memo: pd.get('memo'),
      time: new Date(pd.get('time') * 1000),
      merchant_data: md,
      toAddress: addr.toString(),
      amount: amount,
      network: network,
      domain: opts.host,
      url: opts.url
    });
  });
};


PayPro._getPayProRefundOutputs = function(addrStr, amount) {
  amount = amount.toString(10);

  var output = new BitcorePayPro.Output();
  var addr = new Bitcore.Address(addrStr);

  var s;
  if (addr.isPayToPublicKeyHash()) {
    s = Bitcore.Script.buildPublicKeyHashOut(addr);
  } else if (addr.isPayToScriptHash()) {
    s = Bitcore.Script.buildScriptHashOut(addr);
  } else {
    throw new Error('Unrecognized address type ' + addr.type);
  }

  //  console.log('PayPro refund address set to:', addrStr,s);
  output.set('script', s.toBuffer());
  output.set('amount', amount);
  return [output];
};

PayPro._createJsonPayment = function (currency, rawTx) {
  var payment = {
    currency: currency,
    transactions: [rawTx]
  };
  return JSON.stringify(payment);
};

PayPro._createLegacyPayment = function(merchant_data, rawTx, refundAddr, amountSat) {
  var pay = new BitcorePayPro();
  pay = pay.makePayment();

  if (merchant_data) {
    merchant_data = new Buffer(merchant_data);
    pay.set('merchant_data', merchant_data);
  }

  var txBuf = new Buffer(rawTx, 'hex');
  pay.set('transactions', [txBuf]);

  var refund_outputs = this._getPayProRefundOutputs(refundAddr, amountSat);
  if (refund_outputs)
    pay.set('refund_to', refund_outputs);

  // Unused for now
  // options.memo = '';
  // pay.set('memo', options.memo);

  pay = pay.serialize();
  var buf = new ArrayBuffer(pay.length);
  var view = new Uint8Array(buf);
  for (var i = 0; i < pay.length; i++) {
    view[i] = pay[i];
  }

  return view;
};

PayPro.send = function(opts, cb) {
  $.checkArgument(opts.merchant_data)
    .checkArgument(opts.url)
    .checkArgument(opts.rawTx)
    .checkArgument(opts.refundAddr)
    .checkArgument(opts.amountSat)
    .check(opts.currency);

  PayPro._checkIfJsonIsSupported(opts, function (err, isJsonSupported) {
    if (err) {
      return cb(err);
    }
    if (isJsonSupported) {
      PayPro._sendJson(opts, cb);
    }
    else {
      PayPro._sendLegacy(opts, cb);
    }
  });
};

PayPro._sendJson = function (opts, cb) {
  $.checkArgument(opts.currency)
    .checkArgument(opts.rawTx);

  var payment = PayPro._createJsonPayment(opts.currency, opts.rawTx);

  var http = getHttp(opts);
  opts.method = 'POST';
  opts.headers = opts.headers || {};

  opts.headers.Accept = BitcorePayPro.JSON_PAYMENT_ACK_CONTENT_TYPE; // 'application/payment-ack';
  opts.headers['Content-Type'] = BitcorePayPro.JSON_PAYMENT_CONTENT_TYPE;
  opts.body = payment;

  http(opts, cb);
};

PayPro._sendLegacy = function (opts, cb) {
  $.checkArgument(opts.merchant_data)
    .checkArgument(opts.url)
    .checkArgument(opts.rawTx)
    .checkArgument(opts.refundAddr)
    .checkArgument(opts.amountSat)
    .checkArgument(opts.currency)

  var payment = PayPro._createPayment(opts.merchant_data, opts.rawTx, opts.refundAddr, opts.amountSat);

  var http = getHttp(opts);
  opts.method = 'POST';
  opts.headers = opts.headers || {
    'Accept': BitcorePayPro.LEGACY_PAYMENT[opts.currency].PAYMENT_ACK_CONTENT_TYPE,
    'Content-Type': BitcorePayPro.LEGACY_PAYMENT[opts.currency].CONTENT_TYPE
  };
  opts.body = payment;

  http(opts, function(err, rawData) {
    if (err) return cb(err);
    var memo;
    if (rawData) {
      try {
        var data = BitcorePayPro.PaymentACK.decode(rawData);
        var pp = new BitcorePayPro();
        var ack = pp.makePaymentACK(data);
        memo = ack.get('memo');
      } catch (e) {}
    }
    return cb(null, rawData, memo);
  });
};

module.exports = PayPro;
