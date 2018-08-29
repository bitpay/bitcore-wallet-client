import * as _ from 'lodash';
import * as sjcl from 'sjcl';
import * as b from 'buffer';
import * as Stringify from 'json-stable-stringify';

import * as Bitcore from 'bitcore-lib';
import * as BitcoreCash from 'bitcore-lib-cash';

import { Constants } from './constants';
import { Defaults } from './defaults';

export class Utils {
  private Bitcore_ = {
    btc: Bitcore,
    bch: BitcoreCash
  };
  private PrivateKey = Bitcore.PrivateKey;
  private PublicKey = Bitcore.PublicKey;
  private crypto = Bitcore.crypto;
  private encoding = Bitcore.encoding;

  public SJCL: Function = ()=>{};

  constructor() {
    console.log('Utils class ready!');
  }

  public encryptMessage(message, encryptingKey) {
    const key = sjcl.codec.base64.toBits(encryptingKey);
    return sjcl.encrypt(key, message, _.defaults({
      ks: 128,
      iter: 1,
    }, this.SJCL));
  }

  // Will throw if it can't decrypt
  public decryptMessage(cyphertextJson, encryptingKey) {
    if (!cyphertextJson) return;

    if (!encryptingKey)
      throw 'No key';

    const key = sjcl.codec.base64.toBits(encryptingKey);
    return sjcl.decrypt(key, cyphertextJson);
  }


  public decryptMessageNoThrow(cyphertextJson, encryptingKey) {
    function isJsonString(str) {
      let r;
      try {
        r=JSON.parse(str);
      } catch (e) {
        return false;
      }
      return r;
    }

    if (!encryptingKey)
      return '<ECANNOTDECRYPT>';

    if (!cyphertextJson)
      return '';

    // no sjcl encrypted json
    const r = isJsonString(cyphertextJson);
    if (!r|| !r.iv || !r.ct) {
      return cyphertextJson;
    }

    try {
      return this.decryptMessage(cyphertextJson, encryptingKey);
    } catch (e) {
      return '<ECANNOTDECRYPT>';
    }
  }


  /* TODO: It would be nice to be compatible with bitcoind signmessage. How
   * the hash is calculated there? */
  public hashMessage(text: string) {
    const buf = b.Buffer.from(text);
    let ret = crypto['hash'].sha256sha256(buf); // TODO: review crypto
    ret = new Bitcore.encoding.BufferReader(ret).readReverse();
    return ret;
  }


  public signMessage(text, privKey) {
    const priv = new this.PrivateKey(privKey);
    var hash = this.hashMessage(text);
    return crypto['ECDSA'].sign(hash, priv, 'little').toString();
  }


  public verifyMessage(text, signature, pubKey) {
    if (!signature)
      return false;

    const pub = new this.PublicKey(pubKey);
    const hash = this.hashMessage(text);

    try {
      const sig = new crypto['Signature'].fromString(signature);
      return crypto['ECDSA'].verify(hash, sig, pub, 'little');
    } catch (e) {
      return false;
    }
  }

  public privateKeyToAESKey(privKey: string) {
    if (!Bitcore.PrivateKey.isValid(privKey)) {
      console.log('The private key received is invalid');
      return;
    }
    const pk = Bitcore.PrivateKey.fromString(privKey);
    return Bitcore.crypto.Hash.sha256(pk.toBuffer()).slice(0, 16).toString('base64');
  }

  public getCopayerHash(name, xPubKey, requestPubKey) {
    return [name, xPubKey, requestPubKey].join('|');
  }

  public getProposalHash(proposalHeader) {
    function getOldHash(toAddress, amount, message, payProUrl) {
      return [toAddress, amount, (message || ''), (payProUrl || '')].join('|');
    };

    // For backwards compatibility
    if (arguments.length > 1) {
      return getOldHash.apply(this, arguments);
    }

    return Stringify(proposalHeader);
  }

  public deriveAddress(scriptType, publicKeyRing, path, m, network, coin) {
    if (!_.includes(_.values(Constants.SCRIPT_TYPES), scriptType)) return;

    coin = coin || 'btc';
    const bitcore = this.Bitcore_[coin];
    const publicKeys = _.map(publicKeyRing, (item: any) => {
      var xpub = new bitcore.HDPublicKey(item.xPubKey);
      return xpub.deriveChild(path).publicKey;
    });

    let bitcoreAddress;
    switch (scriptType) {
      case Constants.SCRIPT_TYPES.P2SH:
        bitcoreAddress = bitcore.Address.createMultisig(publicKeys, m, network);
        break;
      case Constants.SCRIPT_TYPES.P2PKH:
        if (!_.isArray(publicKeys) || publicKeys.length != 1) return;
        bitcoreAddress = bitcore.Address.fromPublicKey(publicKeys[0], network);
        break;
    }

    return {
      address: bitcoreAddress.toString(),
      path: path,
      publicKeys: _.invokeMap(publicKeys, 'toString'),
    };
  }

  public xPubToCopayerId(coin, xpub) {
    const str = coin == 'btc' ? xpub : coin + xpub;
    const hash = sjcl.hash.sha256.hash(str);
    return sjcl.codec.hex.fromBits(hash);
  }

  public signRequestPubKey(requestPubKey, xPrivKey) {
    const priv = new Bitcore.HDPrivateKey(xPrivKey).deriveChild(Constants.PATHS.REQUEST_KEY_AUTH).privateKey;
    return this.signMessage(requestPubKey, priv);
  }

  public verifyRequestPubKey(requestPubKey, signature, xPubKey) {
    const pub = (new Bitcore.HDPublicKey(xPubKey)).deriveChild(Constants.PATHS.REQUEST_KEY_AUTH).publicKey;
    return this.verifyMessage(requestPubKey, signature, pub.toString());
  }

  public formatAmount(satoshis, unit, opts) {
    if (!_.includes(_.keys(Constants.UNITS), unit)) return;

    function clipDecimals(n, decimals) {
      const x = n.toString().split('.');
      const d = (x[1] || '0').substring(0, decimals);
      return parseFloat(x[0] + '.' + d);
    };

    function addSeparators(nStr, thousands, decimal, minDecimals) {
      nStr = nStr.replace('.', decimal);
      const x = nStr.split(decimal);
      let x0 = x[0];
      let x1 = x[1];

      x1 = _.dropRightWhile(x1, function(n, i) {
        return n == '0' && i >= minDecimals;
      }).join('');
      
      const x2 = x.length > 1 ? decimal + x1 : '';
      x0 = x0.replace(/\B(?=(\d{3})+(?!\d))/g, thousands);
      return x0 + x2;
    };

    opts = opts || {};

    const u = Constants.UNITS[unit];
    const precision = opts.fullPrecision ? 'full' : 'short';
    const amount = clipDecimals((satoshis / u.toSatoshis), u[precision].maxDecimals).toFixed(u[precision].maxDecimals);
    return addSeparators(amount, opts.thousandsSeparator || ',', opts.decimalSeparator || '.', u[precision].minDecimals);
  }

  public buildTx(txp) {
    const coin = txp.coin || 'btc';

    const bitcore = this.Bitcore_[coin];

    const t = new bitcore.Transaction();

    if (!_.includes(_.values(Constants.SCRIPT_TYPES), txp.addressType)) return;

    switch (txp.addressType) {
      case Constants.SCRIPT_TYPES.P2SH:
        _.each(txp.inputs, function(i) {
          t.from(i, i.publicKeys, txp.requiredSignatures);
        });
        break;
      case Constants.SCRIPT_TYPES.P2PKH:
        t.from(txp.inputs);
        break;
    }

    if (txp.toAddress && txp.amount && !txp.outputs) {
      t.to(txp.toAddress, txp.amount);
    } else if (txp.outputs) {
      _.each(txp.outputs, function(o) {
        if (!o.script && !o.toAddress) {
          console.log('Output should have either toAddress or script specified');  
          return;
        }
        if (o.script) {
          t.addOutput(new bitcore.Transaction.Output({
            script: o.script,
            satoshis: o.amount
          }));
        } else {
          t.to(o.toAddress, o.amount);
        }
      });
    }

    t.fee(txp.fee);
    t.change(txp.changeAddress.address);

    // Shuffle outputs for improved privacy
    if (t.outputs.length > 1) {
      var outputOrder = _.reject(txp.outputOrder, function(order) {
        return order >= t.outputs.length;
      });
      if (t.outputs.length != outputOrder.length) return;
      t.sortOutputs(function(outputs) {
        return _.map(outputOrder, function(i) {
          return outputs[i];
        });
      });
    }

    // Validate inputs vs outputs independently of Bitcore
    var totalInputs = _.reduce(txp.inputs, function(memo, i) {
      return +i.satoshis + memo;
    }, 0);
    var totalOutputs = _.reduce(t.outputs, function(memo, o) {
      return +o.satoshis + memo;
    }, 0);

    if (totalInputs - totalOutputs < 0) return;
    if (totalInputs - totalOutputs > Defaults.MAX_TX_FEE) return;

    return t;
  }
}
