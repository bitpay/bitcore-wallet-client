import * as b from 'buffer';
import * as Bitcore from 'bitcore-lib';
import * as BitcoreCash from 'bitcore-lib-cash';
import * as BitcorePayPro from 'bitcore-payment-protocol';

import * as Http from 'http';
import * as Https from 'https';

import { Logger } from './logger';
const log = new Logger();

export class PayPro {
  private Bitcore_ = {
    btc: Bitcore,
    bch: BitcoreCash
  };

  constructor() {
  }
  
  private nodeRequest(opts, cb) {
    opts.agent = false;
    const http = opts.httpNode || (opts.proto === 'http' ? Http : Https);

    let fn = opts.method == 'POST' ? 'post' : 'get';

    http[fn](opts, function(res) {
      let data: any = []; // List of Buffer objects


      if (res.statusCode != 200)
        return cb(new Error('HTTP Request Error: '  + res.statusCode + ' ' + res.statusMessage + ' ' +  ( data ? data : '' )  ));

      res.on("data", function(chunk) {
        data.push(chunk); // Append Buffer object
      });
      res.on("end", function() {
        data = b.Buffer.concat(data); // Make one large Buffer of it
        return cb(null, data);
      });
    });
  }

  private browserRequest(opts, cb) {
    const method = (opts.method || 'GET').toUpperCase();
    const url = opts.url;
    const req = opts;

    req.headers = req.headers || {};
    req.body = req.body || req.data || '';

    let xhr = opts.xhr || new XMLHttpRequest();
    xhr.open(method, url, true);

    Object.keys(req.headers).forEach(function(key) {
      let val = req.headers[key];
      if (key === 'Content-Length') return;
      if (key === 'Content-Transfer-Encoding') return;
      xhr.setRequestHeader(key, val);
    });
    xhr.responseType = 'arraybuffer';

    xhr.onload = function(event) {
      const response = xhr.response;
      if (xhr.status == 200) {
        return cb(null, new Uint8Array(response));
      } else {
        return cb('HTTP Request Error: '  + xhr.status + ' ' + xhr.statusText + ' ' + response ? response : '');
      }
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
  }

  private getHttp(opts) {
    const match = opts.url.match(/^((http[s]?):\/)?\/?([^:\/\s]+)((\/\w+)*\/)([\w\-\.]+[^#?\s]+)(.*)?(#[\w\-]+)?$/);

    opts.proto = RegExp.$2;
    opts.host = RegExp.$3;
    opts.path = RegExp.$4 + RegExp.$6;
    if (opts.http) return opts.http;

    /* 
     * DEPRECATED
    var env = opts.env;
    if (!env)
      env = (process && !process.browser) ? 'node' : 'browser';

    return (env == "node") ? this.nodeRequest : http = this.browserRequest;;
     */

    return this.nodeRequest;
  }

  public get(opts, cb) {
    // TODO preconditions
    if (!opts || !opts.url) return;

    const http = this.getHttp(opts);
    const coin = opts.coin || 'btc';
    const bitcore = this.Bitcore_[coin];

    const COIN = coin.toUpperCase();
    const PP = new BitcorePayPro(COIN);

    opts.headers = opts.headers || {
      'Accept': BitcorePayPro.LEGACY_PAYMENT[COIN].REQUEST_CONTENT_TYPE,
      'Content-Type': 'application/octet-stream',
    };

    http(opts, function(err, dataBuffer) {
      if (err) return cb(err);
      let request, verified, signature, serializedDetails;
      try {
        const body = BitcorePayPro.PaymentRequest.decode(dataBuffer);
        request = PP.makePaymentRequest(body);
        signature = request.get('signature');
        serializedDetails = request.get('serialized_payment_details');
        // Verify the signature
        verified = request.verify(true);
      } catch (e) {
        return cb(new Error('Could not parse payment protocol' + e));
      }

      // Get the payment details
      let decodedDetails = BitcorePayPro.PaymentDetails.decode(serializedDetails);
      let pd = new BitcorePayPro();
      pd = pd.makePaymentDetails(decodedDetails);

      let outputs = pd.get('outputs');
      if (outputs.length > 1)
        return cb(new Error('Payment Protocol Error: Requests with more that one output are not supported'))

      let output = outputs[0];

      let amount = output.get('amount').toNumber();
      let network = pd.get('network') == 'test' ? 'testnet' : 'livenet';

      // We love payment protocol
      let offset = output.get('script').offset;
      let limit = output.get('script').limit;

      // NOTE: For some reason output.script.buffer
      // is only an ArrayBuffer
      let buffer = new Buffer(new Uint8Array(output.get('script').buffer));
      let scriptBuf = buffer.slice(offset, limit);
      let addr = new bitcore.Address.fromScript(new bitcore.Script(scriptBuf), network);

      let md = pd.get('merchant_data');

      if (md) {
        md = md.toString();
      }

      let ok = verified.verified;
      let caName;

      if (verified.isChain) {
        ok = ok && verified.chainVerified;
      }

      let ret = {
        verified: ok,
        caTrusted: verified.caTrusted,
        caName: verified.caName,
        selfSigned: verified.selfSigned,
        expires: pd.get('expires'),
        memo: pd.get('memo'),
        time: pd.get('time'),
        merchant_data: md,
        toAddress: addr.toString(),
        amount: amount,
        network: network,
        domain: opts.host,
        url: opts.url,
        requiredFeeRate: pd.get('required_fee_rate')
      };

      return cb(null, ret);
    });
  }


  private getPayProRefundOutputs(addrStr, amount, coin) {
    amount = amount.toString(10);

    const bitcore = this.Bitcore_[coin];
    let output = new BitcorePayPro.Output();
    const addr = new bitcore.Address(addrStr);

    let s;
    if (addr.isPayToPublicKeyHash()) {
      s = bitcore.Script.buildPublicKeyHashOut(addr);
    } else if (addr.isPayToScriptHash()) {
      s = bitcore.Script.buildScriptHashOut(addr);
    } else {
      throw new Error('Unrecognized address type ' + addr.type);
    }

    //  console.log('PayPro refund address set to:', addrStr,s);
    output.set('script', s.toBuffer());
    output.set('amount', amount);
    return [output];
  }


  public createPayment = function(merchant_data, rawTx, refundAddr, amountSat, coin) {
    let pay = new BitcorePayPro();
    pay = pay.makePayment();

    if (merchant_data) {
      merchant_data = new Buffer(merchant_data);
      pay.set('merchant_data', merchant_data);
    }

    const txBuf = new Buffer(rawTx, 'hex');
    pay.set('transactions', [txBuf]);

    const refund_outputs = this.getPayProRefundOutputs(refundAddr, amountSat, coin);
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
  }

  public send(opts, cb) {
    if (!opts.merchant_data || !opts.url || !opts.rawTx || !opts.refundAddr || !opts.amountSat) return;

    const coin = opts.coin || 'btc';
    const COIN = coin.toUpperCase();

    const payment = this.createPayment(opts.merchant_data, opts.rawTx, opts.refundAddr, opts.amountSat, coin);

    const http = this.getHttp(opts);
    opts.method = 'POST';
    opts.headers = opts.headers || {
      'Accept': BitcorePayPro.LEGACY_PAYMENT[COIN].ACK_CONTENT_TYPE,
      'Content-Type': BitcorePayPro.LEGACY_PAYMENT[COIN].CONTENT_TYPE,
      // 'Content-Type': 'application/octet-stream',
    };
    opts.body = payment;

    http(opts, (err, rawData) => {
      if (err) return cb(err);
      let memo;
      if (rawData) {
        try {
          var data = BitcorePayPro.PaymentACK.decode(rawData);
          var pp = new BitcorePayPro(COIN);
          var ack = pp.makePaymentACK(data);
          memo = ack.get('memo');
        } catch (e) {
          log.error('Could not decode paymentACK');
        };
      }
      return cb(null, rawData, memo);
    });
  }
}
