import * as _ from 'lodash';
import * as sjcl from 'sjcl';
import * as b from 'buffer';
import * as Stringify from 'json-stable-stringify';
import * as util from 'util';
import * as async from 'async';
import * as events from 'events';

import * as Mnemonic from 'bitcore-mnemonic';
import * as url from'url';
import * as querystring from 'querystring';

import * as request from 'superagent';

import * as Bitcore from 'bitcore-lib';
import * as BitcoreCash from 'bitcore-lib-cash';
import * as Bip38 from 'bip38';

import * as log from './log';

import { Constants } from './common/constants';
import { Defaults } from './common/defaults';
import { Utils } from './common/utils';
import { PayPro } from './paypro';
import { Credentials } from './credentials';
import { Verifier } from './verifier';
import { Errors } from './errors/index';

const Package = require('../package.json');
const BASE_URL = 'http://localhost:3232/bws/api';

export class Client {

  private request;
  private baseUrl;
  private payProHttp;
  private doNotVerifyPayPro;
  private timeout;
  private logLevel;
  private supportStaffWalletId;
  private privateKeyEncryptionOpts;

  private notificationIncludeOwn;
  private lastNotificationId;
  private notificationsIntervalId;

  private credentials;

  private _Utils;
  private _Credentials;
  private _Verifier;
  private _PayPro;
  private _Errors;

  private Bitcore_ = {
    btc: Bitcore,
    bch: BitcoreCash
  };


  private _deviceValidated;
  private keyDerivationOk;
  private session;

  constructor(opts) {

    this._Utils = new Utils();
    this._Credentials = new Credentials();
    this._Verifier = new Verifier();
    this._PayPro = new PayPro();
    this._Errors = new Errors();

    opts = opts || {};
    this.request = opts.request || request;
    this.baseUrl = opts.baseUrl || BASE_URL;
    this.payProHttp = null; // Only for testing
    this.doNotVerifyPayPro = opts.doNotVerifyPayPro;
    this.timeout = opts.timeout || 50000;
    this.logLevel = opts.logLevel || 'silent';
    this.supportStaffWalletId = opts.supportStaffWalletId;

    log.setLevel(this.logLevel);  
    util.inherits(Client, events.EventEmitter);

    this.privateKeyEncryptionOpts = {
      iter: 10000
    };
  }

  public initNotifications(cb) {
    //TODO log.warn('DEPRECATED: use initialize() instead.');
    this.initialize({}, cb);
  };

  public initialize(opts, cb) {
    //TODO $.checkState(this.credentials);

    this.notificationIncludeOwn = !!opts.notificationIncludeOwn;
    this._initNotifications(opts);
    return cb();
  }

  public dispose(cb) {
    this._disposeNotifications();
    this._logout(cb);
  }

  public _fetchLatestNotifications(interval, cb) {
    cb = cb || function() {};

    let opts = {
      lastNotificationId: this.lastNotificationId,
      includeOwn: this.notificationIncludeOwn,
      timeSpan: null
    };

    if (!this.lastNotificationId) {
      opts.timeSpan = interval + 1;
    }

    this.getNotifications(opts, (err, notifications) => {
      if (err) {
        //TODO log.warn('Error receiving notifications.');
        //TODO log.debug(err);
        return cb(err);
      }
      if (notifications.length > 0) {
        this.lastNotificationId = _.last(notifications)['id'];
      }

      _.each(notifications, function(notification) {
        this.emit('notification', notification);
      });
      return cb();
    });
  }

  public _initNotifications(opts) {
    opts = opts || {};

    let interval = opts.notificationIntervalSeconds || 5;
    this.notificationsIntervalId = setInterval(() => {
      this._fetchLatestNotifications(interval, (err) => {
        if (err) {
          if (err instanceof this._Errors.NOT_FOUND || err instanceof this._Errors.NOT_AUTHORIZED) {
            this._disposeNotifications();
          }
        }
      });
    }, interval * 1000);
  }

  public _disposeNotifications() {
    if (this.notificationsIntervalId) {
      clearInterval(this.notificationsIntervalId);
      this.notificationsIntervalId = null;
    }
  }

  /**
   * Reset notification polling with new interval
   * @param {Numeric} notificationIntervalSeconds - use 0 to pause notifications
   */
  public setNotificationsInterval(notificationIntervalSeconds) {
    this._disposeNotifications();
    if (notificationIntervalSeconds > 0) {
      this._initNotifications({
        notificationIntervalSeconds: notificationIntervalSeconds
      });
    }
  }

  /**
   * Encrypt a message
   * @private
   * @static
   * @memberof Client.API
   * @param {String} message
   * @param {String} encryptingKey
   */
  public _encryptMessage(message, encryptingKey) {
    if (!message) return null;
    return this._Utils.encryptMessage(message, encryptingKey);
  }

  public _processTxNotes(notes) {
    if (!notes) return;

    let encryptingKey = this._Credentials.sharedEncryptingKey;
    _.each([].concat(notes), function(note) {
      note.encryptedBody = note.body;
      note.body = this._Utils.decryptMessageNoThrow(note.body, encryptingKey);
      note.encryptedEditedByName = note.editedByName;
      note.editedByName = this._Utils.decryptMessageNoThrow(note.editedByName, encryptingKey);
    });
  }

  /**
   * Decrypt text fields in transaction proposals
   * @private
   * @static
   * @memberof Client.API
   * @param {Array} txps
   * @param {String} encryptingKey
   */
  public _processTxps(txps) {
    if (!txps) return;

    let encryptingKey = this._Credentials.sharedEncryptingKey;
    _.each([].concat(txps), function(txp) {
      txp.encryptedMessage = txp.message;
      txp.message = this._Utils.decryptMessageNoThrow(txp.message, encryptingKey) || null;
      txp.creatorName = this._Utils.decryptMessageNoThrow(txp.creatorName, encryptingKey);

      _.each(txp.actions, function(action) {

        // CopayerName encryption is optional (not available in older wallets)
        action.copayerName = this._Utils.decryptMessageNoThrow(action.copayerName, encryptingKey);

        action.comment = this._Utils.decryptMessageNoThrow(action.comment, encryptingKey);
        // TODO get copayerName from Credentials -> copayerId to copayerName
        // action.copayerName = null;
      });
      _.each(txp.outputs, function(output) {
        output.encryptedMessage = output.message;
        output.message = this._Utils.decryptMessageNoThrow(output.message, encryptingKey) || null;
      });
      txp.hasUnconfirmedInputs = _.some(txp.inputs, function(input) {
        return input.confirmations == 0;
      });
      this._processTxNotes(txp.note);
    });
  }

  /**
   * Parse errors
   * @private
   * @static
   * @memberof Client.API
   * @param {Object} body
   */
  public _parseError(body) {
    if (!body) return;

    if (_.isString(body)) {
      try {
        body = JSON.parse(body);
      } catch (e) {
        body = {
          error: body
        };
      }
    }
    let ret;
    if (body.code) {
      if (this._Errors[body.code]) {
        ret = new this._Errors[body.code];
        if (body.message) ret.message = body.message;
      } else {
        ret = new Error(body.code + ': ' + body.message);
      }
    } else {
      ret = new Error(body.error || JSON.stringify(body));
    }
    // TODO log.error(ret);
    return ret;
  }

  /**
   * Sign an HTTP request
   * @private
   * @static
   * @memberof Client.API
   * @param {String} method - The HTTP method
   * @param {String} url - The URL for the request
   * @param {Object} args - The arguments in case this is a POST/PUT request
   * @param {String} privKey - Private key to sign the request
   */
  public _signRequest(method, url, args, privKey) {
    const message = [method.toLowerCase(), url, JSON.stringify(args)].join('|');
    return this._Utils.signMessage(message, privKey);
  }

  /**
   * Seed from random
   *
   * @param {Object} opts
   * @param {String} opts.coin - default 'btc'
   * @param {String} opts.network - default 'livenet'
   */
  public seedFromRandom(opts) {
    //TODO $.checkArgument(arguments.length <= 1, 'DEPRECATED: only 1 argument accepted.');
    // TODO $.checkArgument(_.isUndefined(opts) || _.isObject(opts), 'DEPRECATED: argument should be an options object.');

    opts = opts || {};
    this.credentials = this._Credentials.create(opts.coin || 'btc', opts.network || 'livenet');
  }

  /**
   * Seed from random
   *
   * @param {Object} opts
   * @param {String} opts.passphrase
   * @param {Boolean} opts.skipDeviceValidation
   */
  public validateKeyDerivation(opts, cb) {
    opts = opts || {};

    let c = this.credentials;

    let testMessageSigning = function(xpriv, xpub) {
      const nonHardenedPath = 'm/0/0';
      const message = 'Lorem ipsum dolor sit amet, ne amet urbanitas percipitur vim, libris disputando his ne, et facer suavitate qui. Ei quidam laoreet sea. Cu pro dico aliquip gubergren, in mundi postea usu. Ad labitur posidonium interesset duo, est et doctus molestie adipiscing.';
      const priv = xpriv.deriveChild(nonHardenedPath).privateKey;
      const signature = this._Utils.signMessage(message, priv);
      const pub = xpub.deriveChild(nonHardenedPath).publicKey;
      return this._Utils.verifyMessage(message, signature, pub);
    };

    let testHardcodedKeys = function() {
      const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      let xpriv = Mnemonic(words).toHDPrivateKey();

      if (xpriv.toString() != 'xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu') return false;

      xpriv = xpriv.deriveChild("m/44'/0'/0'");
      if (xpriv.toString() != 'xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb') return false;

      const xpub = Bitcore.HDPublicKey.fromString('xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj');
      return testMessageSigning(xpriv, xpub);
    };

    let testLiveKeys = function() {
      let words;
      try {
        words = c.getMnemonic();
      } catch (ex) {}

      let xpriv;
      if (words && (!c.mnemonicHasPassphrase || opts.passphrase)) {
        const m = new Mnemonic(words);
        xpriv = m.toHDPrivateKey(opts.passphrase, c.network);
      }
      if (!xpriv) {
        xpriv = new Bitcore.HDPrivateKey(c.xPrivKey);
      }
      xpriv = xpriv.deriveChild(c.getBaseAddressDerivationPath());
      const xpub = new Bitcore.HDPublicKey(c.xPubKey);

      return testMessageSigning(xpriv, xpub);
    };

    let hardcodedOk = true;
    if (!this._deviceValidated && !opts.skipDeviceValidation) {
      hardcodedOk = testHardcodedKeys();
      this._deviceValidated = true;
    }

    let liveOk = (c.canSign() && !c.isPrivKeyEncrypted()) ? testLiveKeys() : true;

    this.keyDerivationOk = hardcodedOk && liveOk;

    return cb(null, this.keyDerivationOk);
  };

  /**
   * Seed from random with mnemonic
   *
   * @param {Object} opts
   * @param {String} opts.coin - default 'btc'
   * @param {String} opts.network - default 'livenet'
   * @param {String} opts.passphrase
   * @param {Number} opts.language - default 'en'
   * @param {Number} opts.account - default 0
   */
  public seedFromRandomWithMnemonic(opts) {
    // TODO $.checkArgument(arguments.length <= 1, 'DEPRECATED: only 1 argument accepted.');
    // TODO $.checkArgument(_.isUndefined(opts) || _.isObject(opts), 'DEPRECATED: argument should be an options object.');

    opts = opts || {};
    this.credentials = this._Credentials.createWithMnemonic(opts.coin || 'btc', opts.network || 'livenet', opts.passphrase, opts.language || 'en', opts.account || 0);
  }

  public getMnemonic() {
    return this.credentials.getMnemonic();
  }

  public mnemonicHasPassphrase() {
    return this.credentials.mnemonicHasPassphrase;
  }

  public clearMnemonic() {
    return this.credentials.clearMnemonic();
  }

  /**
   * Seed from extended private key
   *
   * @param {String} xPrivKey
   * @param {String} opts.coin - default 'btc'
   * @param {Number} opts.account - default 0
   * @param {String} opts.derivationStrategy - default 'BIP44'
   */
  public seedFromExtendedPrivateKey(xPrivKey, opts) {
    opts = opts || {};
    this.credentials = this._Credentials.fromExtendedPrivateKey(opts.coin || 'btc', xPrivKey, opts.account || 0, opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44, opts);
  }

  /**
   * Seed from Mnemonics (language autodetected)
   * Can throw an error if mnemonic is invalid
   *
   * @param {String} BIP39 words
   * @param {Object} opts
   * @param {String} opts.coin - default 'btc'
   * @param {String} opts.network - default 'livenet'
   * @param {String} opts.passphrase
   * @param {Number} opts.account - default 0
   * @param {String} opts.derivationStrategy - default 'BIP44'
   */
  public seedFromMnemonic(words, opts) {
    // TODO $.checkArgument(_.isUndefined(opts) || _.isObject(opts), 'DEPRECATED: second argument should be an options object.');

    opts = opts || {};
    this.credentials = this._Credentials.fromMnemonic(opts.coin || 'btc', opts.network || 'livenet', words, opts.passphrase, opts.account || 0, opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44, opts);
  }

  /**
   * Seed from external wallet public key
   *
   * @param {String} xPubKey
   * @param {String} source - A name identifying the source of the xPrivKey (e.g. ledger, TREZOR, ...)
   * @param {String} entropySourceHex - A HEX string containing pseudo-random data, that can be deterministically derived from the xPrivKey, and should not be derived from xPubKey.
   * @param {Object} opts
   * @param {String} opts.coin - default 'btc'
   * @param {Number} opts.account - default 0
   * @param {String} opts.derivationStrategy - default 'BIP44'
   */
  public seedFromExtendedPublicKey(xPubKey, source, entropySourceHex, opts) {
    // TODO $.checkArgument(_.isUndefined(opts) || _.isObject(opts));

    opts = opts || {};
    this.credentials = this._Credentials.fromExtendedPublicKey(opts.coin || 'btc', xPubKey, source, entropySourceHex, opts.account || 0, opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44);
  }

  /**
   * Export wallet
   *
   * @param {Object} opts
   * @param {Boolean} opts.password
   * @param {Boolean} opts.noSign
   */
  public export(opts) {
    // TODO $.checkState(this.credentials);

    opts = opts || {};

    let output;

    let c = this._Credentials.fromObj(this.credentials);

    if (opts.noSign) {
      c.setNoSign();
    } else if (opts.password) {
      c.decryptPrivateKey(opts.password);
    }

    output = JSON.stringify(c.toObj());

    return output;
  }


  /**
   * Import wallet
   *
   * @param {Object} str - The serialized JSON created with #export
   */
  public import(str) {
    try {
      const credentials = this._Credentials.fromObj(JSON.parse(str));
      this.credentials = credentials;
    } catch (ex) {
      throw new this._Errors.INVALID_BACKUP;
    }
  }

  public _import(cb) {
    // TODO $.checkState(this.credentials);

    // First option, grab wallet info from BWS.
    this.openWallet((err, ret) => {

      // it worked?
      if (!err) return cb(null, ret);

      // Is the error other than "copayer was not found"? || or no priv key.
      if (err instanceof this._Errors.NOT_AUTHORIZED || this.isPrivKeyExternal())
        return cb(err);

      //Second option, lets try to add an access
      // TODO log.info('Copayer not found, trying to add access');
      this.addAccess({}, (err) => {
        if (err) {
          return cb(new this._Errors.WALLET_DOES_NOT_EXIST);
        }

        this.openWallet(cb);
      });
    });
  }

  /**
   * Import from Mnemonics (language autodetected)
   * Can throw an error if mnemonic is invalid
   *
   * @param {String} BIP39 words
   * @param {Object} opts
   * @param {String} opts.coin - default 'btc'
   * @param {String} opts.network - default 'livenet'
   * @param {String} opts.passphrase
   * @param {Number} opts.account - default 0
   * @param {String} opts.derivationStrategy - default 'BIP44'
   * @param {String} opts.entropySourcePath - Only used if the wallet was created on a HW wallet, in which that private keys was not available for all the needed derivations
   * @param {String} opts.walletPrivKey - if available, walletPrivKey for encrypting metadata
   */
  public importFromMnemonic(words, opts, cb) {
    // TODO log.debug('Importing from 12 Words');

    opts = opts || {};

    let derive = function(nonCompliantDerivation) {
      return this._Credentials.fromMnemonic(opts.coin || 'btc', opts.network || 'livenet', words, opts.passphrase, opts.account || 0, opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44, {
        nonCompliantDerivation: nonCompliantDerivation,
        entropySourcePath: opts.entropySourcePath,
        walletPrivKey: opts.walletPrivKey,
      });
    };

    try {
      this.credentials = derive(false);
    } catch (e) {
      // TODO log.info('Mnemonic error:', e);
      return cb(new this._Errors.INVALID_BACKUP);
    }

    this._import((err, ret) => {
      if (!err) return cb(null, ret);
      if (err instanceof this._Errors.INVALID_BACKUP) return cb(err);
      if (err instanceof this._Errors.NOT_AUTHORIZED || err instanceof this._Errors.WALLET_DOES_NOT_EXIST) {
        let altCredentials = derive(true);
        if (altCredentials.xPubKey.toString() == this.credentials.xPubKey.toString()) return cb(err);
        this.credentials = altCredentials;
        return this._import(cb);
      }
      return cb(err);
    });
  }

  /*
   * Import from extended private key
   *
   * @param {String} xPrivKey
   * @param {String} opts.coin - default 'btc'
   * @param {Number} opts.account - default 0
   * @param {String} opts.derivationStrategy - default 'BIP44'
   * @param {String} opts.compliantDerivation - default 'true'
   * @param {String} opts.walletPrivKey - if available, walletPrivKey for encrypting metadata
   * @param {Callback} cb - The callback that handles the response. It returns a flag indicating that the wallet is imported.
   */
  public importFromExtendedPrivateKey(xPrivKey, opts, cb) {
    // TODO log.debug('Importing from Extended Private Key');

    if (!cb) {
      cb = opts;
      opts = {};
      // TODO log.warn('DEPRECATED WARN: importFromExtendedPrivateKey should receive 3 parameters.');
    }

    try {
      this.credentials = this._Credentials.fromExtendedPrivateKey(opts.coin || 'btc', xPrivKey, opts.account || 0, opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44, opts);
    } catch (e) {
      // TODO log.info('xPriv error:', e);
      return cb(new this._Errors.INVALID_BACKUP);
    };

    this._import(cb);
  }

  /**
   * Import from Extended Public Key
   *
   * @param {String} xPubKey
   * @param {String} source - A name identifying the source of the xPrivKey
   * @param {String} entropySourceHex - A HEX string containing pseudo-random data, that can be deterministically derived from the xPrivKey, and should not be derived from xPubKey.
   * @param {Object} opts
   * @param {String} opts.coin - default 'btc'
   * @param {Number} opts.account - default 0
   * @param {String} opts.derivationStrategy - default 'BIP44'
   * @param {String} opts.compliantDerivation - default 'true'
   */
  public importFromExtendedPublicKey(xPubKey, source, entropySourceHex, opts, cb) {
    // TODO
    //$.checkArgument(arguments.length == 5, "DEPRECATED: should receive 5 arguments");
    //$.checkArgument(_.isUndefined(opts) || _.isObject(opts));
    //$.shouldBeFunction(cb);

    opts = opts || {};
    // TODO log.debug('Importing from Extended Private Key');
    try {
      this.credentials = this._Credentials.fromExtendedPublicKey(opts.coin || 'btc', xPubKey, source, entropySourceHex, opts.account || 0, opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44, opts);
    } catch (e) {
      // TODO log.info('xPriv error:', e);
      return cb(new this._Errors.INVALID_BACKUP);
    };

    this._import(cb);
  }

  public decryptBIP38PrivateKey(encryptedPrivateKeyBase58, passphrase, opts, cb) {
    const bip38 = new Bip38();

    let privateKeyWif;
    try {
      privateKeyWif = bip38.decrypt(encryptedPrivateKeyBase58, passphrase);
    } catch (ex) {
      //return cb(new Error('Could not decrypt BIP38 private key', ex));
      return cb(new Error('Could not decrypt BIP38 private key'));
    }

    const privateKey = new Bitcore.PrivateKey(privateKeyWif);
    const address = privateKey.publicKey.toAddress().toString();
    const addrBuff = new Buffer(address, 'ascii');
    const actualChecksum = Bitcore.crypto.Hash.sha256sha256(addrBuff).toString('hex').substring(0, 8);
    const expectedChecksum = Bitcore.encoding.Base58Check.decode(encryptedPrivateKeyBase58).toString('hex').substring(6, 14);

    if (actualChecksum != expectedChecksum)
      return cb(new Error('Incorrect passphrase'));

    return cb(null, privateKeyWif);
  }

  public getBalanceFromPrivateKey(privateKey, coin, cb) {
    if (_.isFunction(coin)) {
      cb = coin;
      coin = 'btc';
    }
    const B = this.Bitcore_[coin];
   
    privateKey = new B.PrivateKey(privateKey);
    const address = privateKey.publicKey.toAddress();
    this.getUtxos({
      addresses: address.toString(),
    }, function(err, utxos) {
      if (err) return cb(err);
      return cb(null, _.sumBy(utxos, 'satoshis'));
    });
  }

  public buildTxFromPrivateKey(privateKey, destinationAddress, opts, cb) {
    opts = opts || {};

    const coin = opts.coin || 'btc';
    const B = this.Bitcore_[coin];
    privateKey = B.PrivateKey(privateKey);
    const address = privateKey.publicKey.toAddress();

    async.waterfall([

      function(next) {
        this.getUtxos({
          addresses: address.toString(),
        }, function(err, utxos) {
          return next(err, utxos);
        });
      },
      function(utxos, next) {
        if (!_.isArray(utxos) || utxos.length == 0) return next(new Error('No utxos found'));

        const fee = opts.fee || 10000;
        const amount = _.sumBy(utxos, 'satoshis') - fee;
        if (amount <= 0) return next(new this._Errors.INSUFFICIENT_FUNDS);

        let tx;
        try {
          const toAddress = B.Address.fromString(destinationAddress);

          tx = new B.Transaction()
            .from(utxos)
            .to(toAddress, amount)
            .fee(fee)
            .sign(privateKey);

          // Make sure the tx can be serialized
          tx.serialize();

        } catch (ex) {
          // TODO log.error('Could not build transaction from private key', ex);
          return next(new this._Errors.COULD_NOT_BUILD_TRANSACTION);
        }
        return next(null, tx);
      }
    ], cb);
  }

  /**
   * Open a wallet and try to complete the public key ring.
   *
   * @param {Callback} cb - The callback that handles the response. It returns a flag indicating that the wallet is complete.
   * @fires API#walletCompleted
   */
  public openWallet = function(cb) {
    // TODO $.checkState(this.credentials);
    if (this.credentials.isComplete() && this.credentials.hasWalletInfo())
      return cb(null, true);

    this._doGetRequest('/v2/wallets/?includeExtendedInfo=1', (err, ret) => {
      if (err) return cb(err);
      let wallet = ret.wallet;

      this._processStatus(ret);

      if (!this.credentials.hasWalletInfo()) {
        let me = _.find(wallet.copayers, {
          id: this.credentials.copayerId
        });
        this.credentials.addWalletInfo(wallet.id, wallet.name, wallet.m, wallet.n, me['name']);
      }

      if (wallet.status != 'complete')
        return cb();

      if (this.credentials.walletPrivKey) {
        if (!this._Verifier.checkCopayers(this.credentials, wallet.copayers)) {
          return cb(new this._Errors.SERVER_COMPROMISED);
        }
      } else {
        // this should only happen in AIR-GAPPED flows
        //TODO log.warn('Could not verify copayers key (missing wallet Private Key)');
      }

      this.credentials.addPublicKeyRing(this._extractPublicKeyRing(wallet.copayers));

      this.emit('walletCompleted', wallet);

      return cb(null, ret);
    });
  }

  public _getHeaders(method, url, args) {
    let headers = {
      'x-client-version': 'bwc-' + Package.version,
    };
    if (this.supportStaffWalletId) {
      headers['x-wallet-id'] = this.supportStaffWalletId;
    }

    return headers;
  }


  /**
   * Do an HTTP request
   * @private
   *
   * @param {Object} method
   * @param {String} url
   * @param {Object} args
   * @param {Callback} cb
   */
  public _doRequest(method, url, args, useSession, cb) {
    let headers = this._getHeaders(method, url, args);

    if (this.credentials) {
      headers['x-identity'] = this.credentials.copayerId;

      if (useSession && this.session) {
        headers['x-session'] = this.session;
      } else {
        let reqSignature;
        const key = args._requestPrivKey || this.credentials.requestPrivKey;
        if (key) {
          delete args['_requestPrivKey'];
          reqSignature = this._signRequest(method, url, args, key);
        }
        headers['x-signature'] = reqSignature;
      }
    }

    let r = this.request[method](this.baseUrl + url);

    r.accept('json');

    _.each(headers, function(v, k) {
      if (v) r.set(k, v);
    });

    if (args) {
      if (method == 'post' || method == 'put') {
        r.send(args);

      } else {
        r.query(args);
      }
    }

    r.timeout(this.timeout);

    r.end((err, res) => {
      if (!res) {
        return cb(new this._Errors.CONNECTION_ERROR);
      }

      if (res.body)

        // TODO
        /*log.debug(util.inspect(res.body, {
          depth: 10
        }));*/

      if (res.status !== 200) {
        if (res.status === 404)
          return cb(new this._Errors.NOT_FOUND);

        if (!res.status)
          return cb(new this._Errors.CONNECTION_ERROR);

        // TODO log.error('HTTP Error:' + res.status);

        if (!res.body)
          return cb(new Error(res.status));

        return cb(this._parseError(res.body));
      }

      if (res.body === '{"error":"read ECONNRESET"}')
        return cb(new this._Errors.ECONNRESET_ERROR(JSON.parse(res.body)));

      return cb(null, res.body, res.header);
    });
  }

  public _login(cb) {
    this._doPostRequest('/v1/login', {}, cb);
  }

  public _logout(cb) {
    this._doPostRequest('/v1/logout', {}, cb);
  }

  /**
   * Do an HTTP request
   * @private
   *
   * @param {Object} method
   * @param {String} url
   * @param {Object} args
   * @param {Callback} cb
   */
  public _doRequestWithLogin(method, url, args, cb) {

    let doLogin = function(cb) {
      this._login(function(err, s) {
        if (err) return cb(err);
        if (!s) return cb(new this._Errors.NOT_AUTHORIZED);
        this.session = s;
        cb();
      });
    };

    async.waterfall([

      function(next) {
        if (this.session) return next();
        doLogin(next);
      },
      function(next) {
        this._doRequest(method, url, args, true, (err, body, header) => {
          if (err && err instanceof this._Errors.NOT_AUTHORIZED) {
            doLogin(function(err) {
              if (err) return next(err);
              return this._doRequest(method, url, args, true, next);
            });
          }
          next(null, body, header);
        });
      },
    ], cb);
  }

  /**
   * Do a POST request
   * @private
   *
   * @param {String} url
   * @param {Object} args
   * @param {Callback} cb
   */
  public _doPostRequest(url, args, cb) {
    return this._doRequest('post', url, args, false, cb);
  }

  public _doPutRequest(url, args, cb) {
    return this._doRequest('put', url, args, false, cb);
  }

  /**
   * Do a GET request
   * @private
   *
   * @param {String} url
   * @param {Callback} cb
   */
  public _doGetRequest(url, cb) {
    url += url.indexOf('?') > 0 ? '&' : '?';
    url += 'r=' + _.random(10000, 99999);
    return this._doRequest('get', url, {}, false, cb);
  }

  public _doGetRequestWithLogin = function(url, cb) {
    url += url.indexOf('?') > 0 ? '&' : '?';
    url += 'r=' + _.random(10000, 99999);
    return this._doRequestWithLogin('get', url, {}, cb);
  }

  /**
   * Do a DELETE request
   * @private
   *
   * @param {String} url
   * @param {Callback} cb
   */
  public _doDeleteRequest(url, cb) {
    return this._doRequest('delete', url, {}, false, cb);
  }

  public _buildSecret(walletId, walletPrivKey, coin, network) {
    if (_.isString(walletPrivKey)) {
      walletPrivKey = Bitcore.PrivateKey.fromString(walletPrivKey);
    }
    const widHex = new Buffer(walletId.replace(/-/g, ''), 'hex');
    const widBase58 = new Bitcore.encoding.Base58(widHex).toString();
    return _.padEnd(widBase58, 22, '0') + walletPrivKey.toWIF() + (network == 'testnet' ? 'T' : 'L') + coin;
  }

  public parseSecret(secret) {
    // TODO $.checkArgument(secret);

    let split = function(str, indexes) {
      let parts = [];
      indexes.push(str.length);
      let i = 0;
      while (i < indexes.length) {
        parts.push(str.substring(i == 0 ? 0 : indexes[i - 1], indexes[i]));
        i++;
      };
      return parts;
    };

    try {
      const secretSplit = split(secret, [22, 74, 75]);
      const widBase58 = secretSplit[0].replace(/0/g, '');
      const widHex = Bitcore.encoding.Base58.decode(widBase58).toString('hex');
      const walletId = split(widHex, [8, 12, 16, 20]).join('-');

      const walletPrivKey = Bitcore.PrivateKey.fromString(secretSplit[1]);
      const networkChar = secretSplit[2];
      const coin = secretSplit[3] || 'btc';

      return {
        walletId: walletId,
        walletPrivKey: walletPrivKey,
        coin: coin,
        network: networkChar == 'T' ? 'testnet' : 'livenet',
      };
    } catch (ex) {
      throw new Error('Invalid secret');
    }
  }

  public getRawTx(txp) {
    var t = this._Utils.buildTx(txp);
    return t.uncheckedSerialize();
  }

  public signTxp(txp, derivedXPrivKey) {
    //Derive proper key to sign, for each input
    let privs = [];
    let derived = {};

    const xpriv = new Bitcore.HDPrivateKey(derivedXPrivKey);

    _.each(txp.inputs, function(i) {
      // TODO $.checkState(i.path, "Input derivation path not available (signing transaction)")
      if (!derived[i.path]) {
        derived[i.path] = xpriv.deriveChild(i.path).privateKey;
        privs.push(derived[i.path]);
      }
    });

    const t = this._Utils.buildTx(txp);

    let signatures = _.map(privs, (priv, i) => { 
      return t.getSignatures(priv);
    });

    signatures = _.map(_.sortBy(_.flatten(signatures), 'inputIndex'), (s) => {
      return s.signature.toDER().toString('hex');
    });

    return signatures;
  }

  public _signTxp(txp, password) {
    const derived = this.credentials.getDerivedXPrivKey(password);
    return this.signTxp(txp, derived);
  }

  public _getCurrentSignatures(txp) {
    let acceptedActions = _.filter(txp.actions, {
      type: 'accept'
    });

    return _.map(acceptedActions, (x: any) => {
      return {
        signatures: x.signatures,
        xpub: x.xpub,
      };
    });
  }

  public _addSignaturesToBitcoreTx(txp, t, signatures, xpub) {
    if (signatures.length != txp.inputs.length)
      throw new Error('Number of signatures does not match number of inputs');

    //TODO $.checkState(txp.coin);

    const bitcore = this.Bitcore_[txp.coin];


    let i = 0,
      x = new bitcore.HDPublicKey(xpub);

    _.each(signatures, (signatureHex) => {
      let input = txp.inputs[i];
      try {
        let signature = bitcore.crypto.Signature.fromString(signatureHex);
        let pub = x.deriveChild(txp.inputPaths[i]).publicKey;
        let s = {
          inputIndex: i,
          signature: signature,
          sigtype: bitcore.crypto.Signature.SIGHASH_ALL | bitcore.crypto.Signature.SIGHASH_FORKID,
          publicKey: pub,
        };
        t.inputs[i].addSignature(t, s);
        i++;
      } catch (e) {} ;
    });

    if (i != txp.inputs.length)
      throw new Error('Wrong signatures');
  }


  public _applyAllSignatures(txp, t) {
    // TODO $.checkState(txp.status == 'accepted');

    const sigs = this._getCurrentSignatures(txp);
    _.each(sigs, (x) => {
      this._addSignaturesToBitcoreTx(txp, t, x.signatures, x.xpub);
    });
  }

  /**
   * Join
   * @private
   *
   * @param {String} walletId
   * @param {String} walletPrivKey
   * @param {String} xPubKey
   * @param {String} requestPubKey
   * @param {String} copayerName
   * @param {Object} Optional args
   * @param {String} opts.customData
   * @param {String} opts.coin
   * @param {Callback} cb
   */
  public _doJoinWallet(walletId, walletPrivKey, xPubKey, requestPubKey, copayerName, opts, cb) {
    // TODO $.shouldBeFunction(cb);

    opts = opts || {};

    // Adds encrypted walletPrivateKey to CustomData
    opts.customData = opts.customData || {};
    opts.customData.walletPrivKey = walletPrivKey.toString();
    const encCustomData = this._Utils.encryptMessage(JSON.stringify(opts.customData), this.credentials.personalEncryptingKey);
    const encCopayerName = this._Utils.encryptMessage(copayerName, this.credentials.sharedEncryptingKey);

    let args = {
      walletId: walletId,
      coin: opts.coin,
      name: encCopayerName,
      xPubKey: xPubKey,
      requestPubKey: requestPubKey,
      customData: encCustomData,
      dryRun: null,
      supportBIP44AndP2PKH: null,
      copayerSignature: null
    };
    if (opts.dryRun) args.dryRun = true;

    if (_.isBoolean(opts.supportBIP44AndP2PKH))
      args.supportBIP44AndP2PKH = opts.supportBIP44AndP2PKH;

    const hash = this._Utils.getCopayerHash(args.name, args.xPubKey, args.requestPubKey);
    args.copayerSignature = this._Utils.signMessage(hash, walletPrivKey);

    const url = '/v2/wallets/' + walletId + '/copayers';
    this._doPostRequest(url, args, (err, body) => {
      if (err) return cb(err);
      this._processWallet(body.wallet);
      return cb(null, body.wallet);
    });
  }

  /**
   * Return if wallet is complete
   */
  public isComplete() {
    return this.credentials && this.credentials.isComplete();
  };

  /**
   * Is private key currently encrypted?
   *
   * @return {Boolean}
   */
  public isPrivKeyEncrypted() {
    return this.credentials && this.credentials.isPrivKeyEncrypted();
  };

  /**
   * Is private key external?
   *
   * @return {Boolean}
   */
  public isPrivKeyExternal() {
    return this.credentials && this.credentials.hasExternalSource();
  };

  /**
   * Get external wallet source name
   *
   * @return {String}
   */
  public getPrivKeyExternalSourceName() {
    return this.credentials ? this.credentials.getExternalSourceName() : null;
  }

  /**
   * Returns unencrypted extended private key and mnemonics
   *
   * @param password
   */
  public getKeys(password) {
    return this.credentials.getKeys(password);
  }

  /**
   * Checks is password is valid
   * Returns null (keys not encrypted), true or false.
   *
   * @param password
   */
  public checkPassword(password) {
    if (!this.isPrivKeyEncrypted()) return;

    try {
      let keys = this.getKeys(password);
      return !!keys.xPrivKey;
    } catch (e) {
      return false;
    };
  }

  /**
   * Can this credentials sign a transaction?
   * (Only returns fail on a 'proxy' setup for airgapped operation)
   *
   * @return {undefined}
   */
  public canSign() {
    return this.credentials && this.credentials.canSign();
  }

  public _extractPublicKeyRing(copayers) {
    return _.map(copayers, (copayer) => {
      let pkr = _.pick(copayer, ['xPubKey', 'requestPubKey']);
      pkr['copayerName'] = copayer.name;
      return pkr;
    });
  }

  /**
   * sets up encryption for the extended private key
   *
   * @param {String} password Password used to encrypt
   * @param {Object} opts optional: SJCL options to encrypt (.iter, .salt, etc).
   * @return {undefined}
   */
  public encryptPrivateKey(password, opts) {
    this.credentials.encryptPrivateKey(password, opts || this.privateKeyEncryptionOpts);
  }

  /**
   * disables encryption for private key.
   *
   * @param {String} password Password used to encrypt
   */
  public decryptPrivateKey(password) {
    return this.credentials.decryptPrivateKey(password);
  }

  /**
   * Get current fee levels for the specified network
   *
   * @param {string} coin - 'btc' (default) or 'bch'
   * @param {string} network - 'livenet' (default) or 'testnet'
   * @param {Callback} cb
   * @returns {Callback} cb - Returns error or an object with status information
   */
  public getFeeLevels(coin, network, cb) {
    // TODO
    //$.checkArgument(coin || _.includes(['btc', 'bch'], coin));
    //$.checkArgument(network || _.includes(['livenet', 'testnet'], network));

    this._doGetRequest('/v2/feelevels/?coin=' + (coin || 'btc') + '&network=' + (network || 'livenet'), function(err, result) {
      if (err) return cb(err);
      return cb(err, result);
    });
  }

  /**
   * Get service version
   *
   * @param {Callback} cb
   */
  public getVersion(cb) {
    this._doGetRequest('/v1/version/', cb);
  }

  public _checkKeyDerivation() {
    const isInvalid = (this.keyDerivationOk === false);
    if (isInvalid) {
      // TODO
      //log.error('Key derivation for this device is not working as expected');
    }
    return !isInvalid;
  }

  /**
   *
   * Create a wallet.
   * @param {String} walletName
   * @param {String} copayerName
   * @param {Number} m
   * @param {Number} n
   * @param {object} opts (optional: advanced options)
   * @param {string} opts.coin[='btc'] - The coin for this wallet (btc, bch).
   * @param {string} opts.network[='livenet']
   * @param {string} opts.singleAddress[=false] - The wallet will only ever have one address.
   * @param {String} opts.walletPrivKey - set a walletPrivKey (instead of random)
   * @param {String} opts.id - set a id for wallet (instead of server given)
   * @param cb
   * @return {undefined}
   */
  public createWallet(walletName, copayerName, m, n, opts, cb) {
    if (!this._checkKeyDerivation()) return cb(new Error('Cannot create new wallet'));

    //TODO
    //if (opts) $.shouldBeObject(opts);
    opts = opts || {};

    const coin = opts.coin || 'btc';
    if (!_.includes(['btc', 'bch'], coin)) return cb(new Error('Invalid coin'));

    const network = opts.network || 'livenet';
    if (!_.includes(['testnet', 'livenet'], network)) return cb(new Error('Invalid network'));

    if (!this.credentials) {
      //TODO
      //log.info('Generating new keys');
      this.seedFromRandom({
        coin: coin,
        network: network
      });
    } else {
      //TODO
      //log.info('Using existing keys');
    }

    if (coin != this.credentials.coin) {
      return cb(new Error('Existing keys were created for a different coin'));
    }

    if (network != this.credentials.network) {
      return cb(new Error('Existing keys were created for a different network'));
    }

    const walletPrivKey = opts.walletPrivKey || new Bitcore.PrivateKey();

    let c = this.credentials;
    c.addWalletPrivateKey(walletPrivKey.toString());
    let encWalletName = this._Utils.encryptMessage(walletName, c.sharedEncryptingKey);

    let args = {
      name: encWalletName,
      m: m,
      n: n,
      pubKey: (new Bitcore.PrivateKey(walletPrivKey)).toPublicKey().toString(),
      coin: coin,
      network: network,
      singleAddress: !!opts.singleAddress,
      id: opts.id,
    };
    this._doPostRequest('/v2/wallets/', args, function(err, res) {
      if (err) return cb(err);

      const walletId = res.walletId;
      c.addWalletInfo(walletId, walletName, m, n, copayerName);
      const secret = this._buildSecret(c.walletId, c.walletPrivKey, c.coin, c.network);

      this._doJoinWallet(walletId, walletPrivKey, c.xPubKey, c.requestPubKey, copayerName, {
          coin: coin
        },
        function(err, wallet) {
          if (err) return cb(err);
          return cb(null, n > 1 ? secret : null);
        });
    });
  }

  /**
   * Join an existent wallet
   *
   * @param {String} secret
   * @param {String} copayerName
   * @param {Object} opts
   * @param {string} opts.coin[='btc'] - The expected coin for this wallet (btc, bch).
   * @param {Boolean} opts.dryRun[=false] - Simulate wallet join
   * @param {Callback} cb
   * @returns {Callback} cb - Returns the wallet
   */
  public joinWallet(secret, copayerName, opts, cb) {

    if (!cb) {
      cb = opts;
      opts = {};
      //TODO
      //log.warn('DEPRECATED WARN: joinWallet should receive 4 parameters.');
    }

    if (!this._checkKeyDerivation()) return cb(new Error('Cannot join wallet'));

    opts = opts || {};

    const coin = opts.coin || 'btc';
    if (!_.includes(['btc', 'bch'], coin)) return cb(new Error('Invalid coin'));

    let secretData;
    try {
      secretData = this.parseSecret(secret);
    } catch (ex) {
      return cb(ex);
    }

    if (!this.credentials) {
      this.seedFromRandom({
        coin: coin,
        network: secretData.network
      });
    }

    this.credentials.addWalletPrivateKey(secretData.walletPrivKey.toString());
    this._doJoinWallet(secretData.walletId, secretData.walletPrivKey, this.credentials.xPubKey, this.credentials.requestPubKey, copayerName, {
      coin: coin,
      dryRun: !!opts.dryRun,
    }, function(err, wallet) {
      if (err) return cb(err);
      if (!opts.dryRun) {
        this.credentials.addWalletInfo(wallet.id, wallet.name, wallet.m, wallet.n, copayerName);
      }
      return cb(null, wallet);
    });
  }

  /**
   * Recreates a wallet, given credentials (with wallet id)
   *
   * @returns {Callback} cb - Returns the wallet
   */
  public recreateWallet(cb) {
    //TODO
    //$.checkState(this.credentials);
    //$.checkState(this.credentials.isComplete());
    //$.checkState(this.credentials.walletPrivKey);
    //$.checkState(this.credentials.hasWalletInfo());

    // First: Try to get the wallet with current credentials
    this.getStatus({
      includeExtendedInfo: true
    }, function(err) {
      // No error? -> Wallet is ready.
      if (!err) {
        //TODO
        //log.info('Wallet is already created');
        return cb();
      };

      const c = this.credentials;
      const walletPrivKey = Bitcore.PrivateKey.fromString(c.walletPrivKey);
      let walletId = c.walletId;
      const supportBIP44AndP2PKH = c.derivationStrategy != Constants.DERIVATION_STRATEGIES.BIP45;
      const encWalletName = this._Utils.encryptMessage(c.walletName || 'recovered wallet', c.sharedEncryptingKey);
      const coin = c.coin;

      let args = {
        name: encWalletName,
        m: c.m,
        n: c.n,
        pubKey: walletPrivKey.toPublicKey().toString(),
        coin: c.coin,
        network: c.network,
        id: walletId,
        supportBIP44AndP2PKH: supportBIP44AndP2PKH,
      };

      this._doPostRequest('/v2/wallets/', args, function(err, body) {
        if (err) {
          if (!(err instanceof this._Errors.WALLET_ALREADY_EXISTS))
            return cb(err);

          return this.addAccess({}, function(err) {
            if (err) return cb(err);
            this.openWallet(function(err) {
              return cb(err);
            });
          });
        }

        if (!walletId) {
          walletId = body.walletId;
        }

        let i = 1;
        async.each(this.credentials.publicKeyRing, function(item, next) {
          var name = item.copayerName || ('copayer ' + i++);
          this._doJoinWallet(walletId, walletPrivKey, item.xPubKey, item.requestPubKey, name, {
            coin: c.coin,
            supportBIP44AndP2PKH: supportBIP44AndP2PKH,
          }, function(err) {
            //Ignore error is copayer already in wallet
            if (err && err instanceof this._Errors.COPAYER_IN_WALLET) return next();
            return next(err);
          });
        }, cb);
      });
    });
  }

  public _processWallet(wallet) {

    const encryptingKey = this.credentials.sharedEncryptingKey;

    let name = this._Utils.decryptMessageNoThrow(wallet.name, encryptingKey);
    if (name != wallet.name) {
      wallet.encryptedName = wallet.name;
    }
    wallet.name = name;
    _.each(wallet.copayers, function(copayer) {
      name = this._Utils.decryptMessageNoThrow(copayer.name, encryptingKey);
      if (name != copayer.name) {
        copayer.encryptedName = copayer.name;
      }
      copayer.name = name;
      _.each(copayer.requestPubKeys, function(access) {
        if (!access.name) return;

        name = this._Utils.decryptMessageNoThrow(access.name, encryptingKey);
        if (name != access.name) {
          access.encryptedName = access.name;
        }
        access.name = name;
      });
    });
  }

  public _processStatus(status) {
    let processCustomData = function(data) {
      const copayers = data.wallet.copayers;
      if (!copayers) return;

      let me = _.find(copayers, {
        'id': this.credentials.copayerId
      });
      if (!me || !me['customData']) return;

      let customData;
      try {
        customData = JSON.parse(this._Utils.decryptMessage(me['customData'], this.credentials.personalEncryptingKey));
      } catch (e) {
        //TODO
        //log.warn('Could not decrypt customData:', me.customData);
      }
      if (!customData) return;

      // Add it to result
      data.customData = customData;

      // Update walletPrivateKey
      if (!this.credentials.walletPrivKey && customData.walletPrivKey)
        this.credentials.addWalletPrivateKey(customData.walletPrivKey);
    };

    processCustomData(status);
    this._processWallet(status.wallet);
    this._processTxps(status.pendingTxps);
  }


  /**
   * Get latest notifications
   *
   * @param {object} opts
   * @param {String} opts.lastNotificationId (optional) - The ID of the last received notification
   * @param {String} opts.timeSpan (optional) - A time window on which to look for notifications (in seconds)
   * @param {String} opts.includeOwn[=false] (optional) - Do not ignore notifications generated by the current copayer
   * @returns {Callback} cb - Returns error or an array of notifications
   */
  public getNotifications(opts, cb) {
    //TODO
    //$.checkState(this.credentials);

    opts = opts || {};

    let url = '/v1/notifications/';
    if (opts.lastNotificationId) {
      url += '?notificationId=' + opts.lastNotificationId;
    } else if (opts.timeSpan) {
      url += '?timeSpan=' + opts.timeSpan;
    }

    this._doGetRequestWithLogin(url, function(err, result) {
      if (err) return cb(err);

      let notifications = _.filter(result, function(notification) {
        return opts.includeOwn || (notification.creatorId != this.credentials.copayerId);
      });

      return cb(null, notifications);
    });
  }

  /**
   * Get status of the wallet
   *
   * @param {Boolean} opts.twoStep[=false] - Optional: use 2-step balance computation for improved performance
   * @param {Boolean} opts.includeExtendedInfo (optional: query extended status)
   * @returns {Callback} cb - Returns error or an object with status information
   */
  public getStatus(opts, cb) {
    //TODO
    //$.checkState(this.credentials);

    if (!cb) {
      cb = opts;
      opts = {};
      //TODO
      //log.warn('DEPRECATED WARN: getStatus should receive 2 parameters.')
    }

    opts = opts || {};

    let qs = [];
    qs.push('includeExtendedInfo=' + (opts.includeExtendedInfo ? '1' : '0'));
    qs.push('twoStep=' + (opts.twoStep ? '1' : '0'));

    this._doGetRequest('/v2/wallets/?' + qs.join('&'), function(err, result) {
      if (err) return cb(err);
      if (result.wallet.status == 'pending') {
        const c = this.credentials;
        result.wallet.secret = this._buildSecret(c.walletId, c.walletPrivKey, c.coin, c.network);
      }

      this._processStatus(result);

      return cb(err, result);
    });
  }

  /**
   * Get copayer preferences
   *
   * @param {Callback} cb
   * @return {Callback} cb - Return error or object
   */
  public getPreferences(cb) {
    //TODO
    //$.checkState(this.credentials);
    //$.checkArgument(cb);

    this._doGetRequest('/v1/preferences/', (err, preferences) => {
      if (err) return cb(err);
      return cb(null, preferences);
    });
  }

  /**
   * Save copayer preferences
   *
   * @param {Object} preferences
   * @param {Callback} cb
   * @return {Callback} cb - Return error or object
   */
  public savePreferences(preferences, cb) {
    //TODO
    //$.checkState(this.credentials);
    //$.checkArgument(cb);

    this._doPutRequest('/v1/preferences/', preferences, cb);
  }

  /**
   * fetchPayPro
   *
   * @param opts.payProUrl  URL for paypro request
   * @returns {Callback} cb - Return error or the parsed payment protocol request
   * Returns (err,paypro)
   *  paypro.amount
   *  paypro.toAddress
   *  paypro.memo
   */
  public fetchPayPro(opts, cb) {
    //TODO
    //$.checkArgument(opts)
      //.checkArgument(opts.payProUrl);
   
    this._PayPro.get({
      url: opts.payProUrl,
      http: this.payProHttp,
      coin: this.credentials.coin || 'btc',
    }, function(err, paypro) { 
      if (err)
        return cb(err);

      return cb(null, paypro);
    });
  }

  /**
   * Gets list of utxos
   *
   * @param {Function} cb
   * @param {Object} opts
   * @param {Array} opts.addresses (optional) - List of addresses from where to fetch UTXOs.
   * @returns {Callback} cb - Return error or the list of utxos
   */
  public getUtxos(opts, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());
    opts = opts || {};
    let url = '/v1/utxos/';
    if (opts.addresses) {
      url += '?' + querystring.stringify({
        addresses: [].concat(opts.addresses).join(',')
      });
    }
    this._doGetRequest(url, cb);
  }

  public _getCreateTxProposalArgs(opts) {

    const args = _.cloneDeep(opts);
    args.message = this._encryptMessage(opts.message, this.credentials.sharedEncryptingKey) || null;
    args.payProUrl = opts.payProUrl || null;
    _.each(args.outputs, function(o) {
      o.message = this._encryptMessage(o.message, this.credentials.sharedEncryptingKey) || null;
    });

    return args;
  }

  /**
   * Create a transaction proposal
   *
   * @param {Object} opts
   * @param {string} opts.txProposalId - Optional. If provided it will be used as this TX proposal ID. Should be unique in the scope of the wallet.
   * @param {Array} opts.outputs - List of outputs.
   * @param {string} opts.outputs[].toAddress - Destination address.
   * @param {number} opts.outputs[].amount - Amount to transfer in satoshi.
   * @param {string} opts.outputs[].message - A message to attach to this output.
   * @param {string} opts.message - A message to attach to this transaction.
   * @param {number} opts.feeLevel[='normal'] - Optional. Specify the fee level for this TX ('priority', 'normal', 'economy', 'superEconomy').
   * @param {number} opts.feePerKb - Optional. Specify the fee per KB for this TX (in satoshi).
   * @param {string} opts.changeAddress - Optional. Use this address as the change address for the tx. The address should belong to the wallet. In the case of singleAddress wallets, the first main address will be used.
   * @param {Boolean} opts.sendMax - Optional. Send maximum amount of funds that make sense under the specified fee/feePerKb conditions. (defaults to false).
   * @param {string} opts.payProUrl - Optional. Paypro URL for peers to verify TX
   * @param {Boolean} opts.excludeUnconfirmedUtxos[=false] - Optional. Do not use UTXOs of unconfirmed transactions as inputs
   * @param {Boolean} opts.validateOutputs[=true] - Optional. Perform validation on outputs.
   * @param {Boolean} opts.dryRun[=false] - Optional. Simulate the action but do not change server state.
   * @param {Array} opts.inputs - Optional. Inputs for this TX
   * @param {number} opts.fee - Optional. Use an fixed fee for this TX (only when opts.inputs is specified)
   * @param {Boolean} opts.noShuffleOutputs - Optional. If set, TX outputs won't be shuffled. Defaults to false
   * @returns {Callback} cb - Return error or the transaction proposal
   */
  public createTxProposal(opts, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());
    //$.checkState(this.credentials.sharedEncryptingKey);
    //$.checkArgument(opts);

    var args = this._getCreateTxProposalArgs(opts);

    this._doPostRequest('/v2/txproposals/', args, (err, txp) => {
      if (err) return cb(err);

      this._processTxps(txp);
      if (!this._Verifier.checkProposalCreation(args, txp, this.credentials.sharedEncryptingKey)) {
        return cb(new this._Errors.SERVER_COMPROMISED);
      }

      return cb(null, txp);
    });
  }

  /**
   * Publish a transaction proposal
   *
   * @param {Object} opts
   * @param {Object} opts.txp - The transaction proposal object returned by the API#createTxProposal method
   * @returns {Callback} cb - Return error or null
   */
  public publishTxProposal(opts, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());
    //$.checkArgument(opts)
      //.checkArgument(opts.txp);

    //$.checkState(parseInt(opts.txp.version) >= 3);

    const t = this._Utils.buildTx(opts.txp);
    const hash = t.uncheckedSerialize();
    const args = {
      proposalSignature: this._Utils.signMessage(hash, this.credentials.requestPrivKey)
    };

    const url = '/v1/txproposals/' + opts.txp.id + '/publish/';
    this._doPostRequest(url, args, (err, txp) => {
      if (err) return cb(err);
      this._processTxps(txp);
      return cb(null, txp);
    });
  }

  /**
   * Create a new address
   *
   * @param {Object} opts
   * @param {Boolean} opts.ignoreMaxGap[=false]
   * @param {Callback} cb
   * @returns {Callback} cb - Return error or the address
   */
  public createAddress(opts, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());

    if (!cb) {
      cb = opts;
      opts = {};
      //TODO
      //log.warn('DEPRECATED WARN: createAddress should receive 2 parameters.')
    }

    if (!this._checkKeyDerivation()) return cb(new Error('Cannot create new address for this wallet'));

    opts = opts || {};

    this._doPostRequest('/v3/addresses/', opts, (err, address) => {
      if (err) return cb(err);

      if (!this._Verifier.checkAddress(this.credentials, address)) {
        return cb(new this._Errors.SERVER_COMPROMISED);
      }

      return cb(null, address);
    });
  }

  /**
   * Get your main addresses
   *
   * @param {Object} opts
   * @param {Boolean} opts.doNotVerify
   * @param {Numeric} opts.limit (optional) - Limit the resultset. Return all addresses by default.
   * @param {Boolean} [opts.reverse=false] (optional) - Reverse the order of returned addresses.
   * @param {Callback} cb
   * @returns {Callback} cb - Return error or the array of addresses
   */
  public getMainAddresses(opts, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());

    opts = opts || {};

    let args = [];
    if (opts.limit) args.push('limit=' + opts.limit);
    if (opts.reverse) args.push('reverse=1');
    let qs = '';
    if (args.length > 0) {
      qs = '?' + args.join('&');
    }
    let url = '/v1/addresses/' + qs;

    this._doGetRequest(url, function(err, addresses) {
      if (err) return cb(err);

      if (!opts.doNotVerify) {
        let fake = _.some(addresses, function(address) {
          return !this._Verifier.checkAddress(this.credentials, address);
        });
        if (fake)
          return cb(new this._Errors.SERVER_COMPROMISED);
      }
      return cb(null, addresses);
    });
  }

  /**
   * Update wallet balance
   *
   * @param {String} opts.coin - Optional: defaults to current wallet coin
   * @param {Boolean} opts.twoStep[=false] - Optional: use 2-step balance computation for improved performance
   * @param {Callback} cb
   */
  public getBalance(opts, cb) {
    if (!cb) {
      cb = opts;
      opts = {};
      //TODO
      //log.warn('DEPRECATED WARN: getBalance should receive 2 parameters.')
    }

    opts = opts || {};

    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());

    let args = [];
    if (opts.twoStep) args.push('?twoStep=1');
    if (opts.coin) {
      if (!_.includes(['btc', 'bch'], opts.coin)) return cb(new Error('Invalid coin'));
      args.push('coin=' + opts.coin);
    }
    let qs = '';
    if (args.length > 0) {
      qs = '?' + args.join('&');
    }

    const url = '/v1/balance/' + qs;
    this._doGetRequest(url, cb);
  }

  /**
   * Get list of transactions proposals
   *
   * @param {Object} opts
   * @param {Boolean} opts.doNotVerify
   * @param {Boolean} opts.forAirGapped
   * @param {Boolean} opts.doNotEncryptPkr
   * @return {Callback} cb - Return error or array of transactions proposals
   */
  public getTxProposals(opts, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());

    this._doGetRequest('/v1/txproposals/', function(err, txps) {
      if (err) return cb(err);

      this._processTxps(txps);
      async.every(txps,
        function(txp, acb) {
          if (opts.doNotVerify) return acb(true);
          this.getPayPro(txp, function(err, paypro) {

            var isLegit = this._Verifier.checkTxProposal(this.credentials, txp, {
              paypro: paypro,
            });

            return acb(isLegit);
          });
        },
        function(isLegit) {
          if (!isLegit)
            return cb(new this._Errors.SERVER_COMPROMISED);

          var result;
          if (opts.forAirGapped) {
            result = {
              txps: JSON.parse(JSON.stringify(txps)),
              encryptedPkr: opts.doNotEncryptPkr ? null : this._Utils.encryptMessage(JSON.stringify(this.credentials.publicKeyRing), this.credentials.personalEncryptingKey),
              unencryptedPkr: opts.doNotEncryptPkr ? JSON.stringify(this.credentials.publicKeyRing) : null,
              m: this.credentials.m,
              n: this.credentials.n,
            };
          } else {
            result = txps;
          }
          return cb(null, result);
        });
    });
  }


  //private?
  public getPayPro(txp, cb) {
    if (!txp.payProUrl || this.doNotVerifyPayPro)
      return cb();

    this._PayPro.get({
      url: txp.payProUrl,
      http: this.payProHttp,
      coin: txp.coin || 'btc',
    }, function(err, paypro) {
      if (err) return cb(new Error('Cannot check transaction now:' + err));
      return cb(null, paypro);
    });
  }


  /**
   * Sign a transaction proposal
   *
   * @param {Object} txp
   * @param {String} password - (optional) A password to decrypt the encrypted private key (if encryption is set).
   * @param {Callback} cb
   * @return {Callback} cb - Return error or object
   */
  public signTxProposal(txp, password, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());
    //$.checkArgument(txp.creatorId);

    if (_.isFunction(password)) {
      cb = password;
      password = null;
    }

    if (!txp.signatures) {
      if (!this.canSign())
        return cb(new this._Errors.MISSING_PRIVATE_KEY);

      if (this.isPrivKeyEncrypted() && !password)
        return cb(new this._Errors.ENCRYPTED_PRIVATE_KEY);
    }

    this.getPayPro(txp, function(err, paypro) {
      if (err) return cb(err);

      let isLegit = this._Verifier.checkTxProposal(this.credentials, txp, {
        paypro: paypro,
      });

      if (!isLegit)
        return cb(new this._Errors.SERVER_COMPROMISED);

      let signatures = txp.signatures;

      if (_.isEmpty(signatures)) {
        try {
          signatures = this._signTxp(txp, password);
        } catch (ex) {
          //TODO
          //log.error('Error signing tx', ex);
          return cb(ex);
        }
      }

      const url = '/v1/txproposals/' + txp.id + '/signatures/';
      const args = {
        signatures: signatures
      };

      this._doPostRequest(url, args, function(err, txp) {
        if (err) return cb(err);
        this._processTxps(txp);
        return cb(null, txp);
      });
    });
  }

  /**
   * Sign transaction proposal from AirGapped
   *
   * @param {Object} txp
   * @param {String} encryptedPkr
   * @param {Number} m
   * @param {Number} n
   * @param {String} password - (optional) A password to decrypt the encrypted private key (if encryption is set).
   * @return {Object} txp - Return transaction
   */
  public signTxProposalFromAirGapped(txp, encryptedPkr, m, n, password) {
    //TODO
    //$.checkState(this.credentials);

    if (!this.canSign())
      throw new this._Errors.MISSING_PRIVATE_KEY;

    if (this.isPrivKeyEncrypted() && !password)
      throw new this._Errors.ENCRYPTED_PRIVATE_KEY;

    var publicKeyRing;
    try {
      publicKeyRing = JSON.parse(this._Utils.decryptMessage(encryptedPkr, this.credentials.personalEncryptingKey));
    } catch (ex) {
      throw new Error('Could not decrypt public key ring');
    }

    if (!_.isArray(publicKeyRing) || publicKeyRing.length != n) {
      throw new Error('Invalid public key ring');
    }

    this.credentials.m = m;
    this.credentials.n = n;
    this.credentials.addressType = txp.addressType;
    this.credentials.addPublicKeyRing(publicKeyRing);

    if (!this._Verifier.checkTxProposalSignature(this.credentials, txp))
      throw new Error('Fake transaction proposal');

    return this._signTxp(txp, password);
  }


  /**
   * Sign transaction proposal from AirGapped
   *
   * @param {String} key - A mnemonic phrase or an xprv HD private key
   * @param {Object} txp
   * @param {String} unencryptedPkr
   * @param {Number} m
   * @param {Number} n
   * @param {Object} opts
   * @param {String} opts.coin (default 'btc')
   * @param {String} opts.passphrase
   * @param {Number} opts.account - default 0
   * @param {String} opts.derivationStrategy - default 'BIP44'
   * @return {Object} txp - Return transaction
   */
  // TODO DUPLICATED??????? changed function name and added "cb"
  public signTxProposalFromAirGapped2(key, txp, unencryptedPkr, m, n, opts, cb) {
    opts = opts || {}

    const coin = opts.coin || 'btc';
    if (!_.includes(['btc', 'bch'], coin)) return cb(new Error('Invalid coin'));

    const publicKeyRing = JSON.parse(unencryptedPkr);

    if (!_.isArray(publicKeyRing) || publicKeyRing.length != n) {
      throw new Error('Invalid public key ring');
    }

    let newClient = new Client({
      baseUrl: 'https://bws.example.com/bws/api'
    });

    if (key.slice(0, 4) === 'xprv' || key.slice(0, 4) === 'tprv') {
      if (key.slice(0, 4) === 'xprv' && txp.network == 'testnet') throw new Error("testnet HD keys must start with tprv");
      if (key.slice(0, 4) === 'tprv' && txp.network == 'livenet') throw new Error("livenet HD keys must start with xprv");
      newClient.seedFromExtendedPrivateKey(key, {
        'coin': coin,
        'account': opts.account,
        'derivationStrategy': opts.derivationStrategy
      });
    } else {
      newClient.seedFromMnemonic(key, {
        'coin': coin,
        'network': txp.network,
        'passphrase': opts.passphrase,
        'account': opts.account,
        'derivationStrategy': opts.derivationStrategy
      })
    }
    newClient.credentials.m = m;
    newClient.credentials.n = n;
    newClient.credentials.addressType = txp.addressType;
    newClient.credentials.addPublicKeyRing(publicKeyRing);

    if (!this._Verifier.checkTxProposalSignature(newClient.credentials, txp))
      throw new Error('Fake transaction proposal');

    return newClient._signTxp(txp, null);
  }


  /**
   * Reject a transaction proposal
   *
   * @param {Object} txp
   * @param {String} reason
   * @param {Callback} cb
   * @return {Callback} cb - Return error or object
   */
  public rejectTxProposal(txp, reason, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());
    //$.checkArgument(cb);

    const url = '/v1/txproposals/' + txp.id + '/rejections/';
    const args = {
      reason: this._encryptMessage(reason, this.credentials.sharedEncryptingKey) || '',
    };
    this._doPostRequest(url, args, (err, txp) => {
      if (err) return cb(err);
      this._processTxps(txp);
      return cb(null, txp);
    });
  }

  /**
   * Broadcast raw transaction
   *
   * @param {Object} opts
   * @param {String} opts.network
   * @param {String} opts.rawTx
   * @param {Callback} cb
   * @return {Callback} cb - Return error or txid
   */
  public broadcastRawTx(opts, cb) {
    //TODO
    //$.checkState(this.credentials);
    //$.checkArgument(cb);

    opts = opts || {};

    const url = '/v1/broadcast_raw/';
    this._doPostRequest(url, opts, (err, txid) => {
      if (err) return cb(err);
      return cb(null, txid);
    });
  }

  public _doBroadcast(txp, cb) {
    const url = '/v1/txproposals/' + txp.id + '/broadcast/';
    this._doPostRequest(url, {}, (err, txp) => {
      if (err) return cb(err);
      this._processTxps(txp);
      return cb(null, txp);
    });
  }


  /**
   * Broadcast a transaction proposal
   *
   * @param {Object} txp
   * @param {Callback} cb
   * @return {Callback} cb - Return error or object
   */
  public broadcastTxProposal(txp, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());

    this.getPayPro(txp, function(err, paypro) {

      if (paypro) {

        let t = this._Utils.buildTx(txp);
        this._applyAllSignatures(txp, t);

        this._PayPro.send({
          http: this.payProHttp,
          url: txp.payProUrl,
          amountSat: txp.amount,
          refundAddr: txp.changeAddress.address,
          merchant_data: paypro.merchant_data,
          rawTx: t.serialize({
            disableSmallFees: true,
            disableLargeFees: true,
            disableDustOutputs: true
          }),
          coin: txp.coin || 'btc',
        }, function(err, ack, memo) {
          if (err) return cb(err);
          this._doBroadcast(txp, (err, txp) => {
            return cb(err, txp, memo);
          });
        });
      } else {
        this._doBroadcast(txp, cb);
      }
    });
  }

  /**
   * Remove a transaction proposal
   *
   * @param {Object} txp
   * @param {Callback} cb
   * @return {Callback} cb - Return error or empty
   */
  public removeTxProposal(txp, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());

    const url = '/v1/txproposals/' + txp.id;
    this._doDeleteRequest(url, (err) => {
      return cb(err);
    });
  }

  /**
   * Get transaction history
   *
   * @param {Object} opts
   * @param {Number} opts.skip (defaults to 0)
   * @param {Number} opts.limit
   * @param {Boolean} opts.includeExtendedInfo
   * @param {Callback} cb
   * @return {Callback} cb - Return error or array of transactions
   */
  public getTxHistory = function(opts, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());

    let args = [];
    if (opts) {
      if (opts.skip) args.push('skip=' + opts.skip);
      if (opts.limit) args.push('limit=' + opts.limit);
      if (opts.includeExtendedInfo) args.push('includeExtendedInfo=1');
    }
    let qs = '';
    if (args.length > 0) {
      qs = '?' + args.join('&');
    }

    const url = '/v1/txhistory/' + qs;
    this._doGetRequest(url, (err, txs) => {
      if (err) return cb(err);
      this._processTxps(txs);
      return cb(null, txs);
    });
  }

  /**
   * getTx
   *
   * @param {String} TransactionId
   * @return {Callback} cb - Return error or transaction
   */
  public getTx(id, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());

    const url = '/v1/txproposals/' + id;
    this._doGetRequest(url, (err, txp) => {
      if (err) return cb(err);

      this._processTxps(txp);
      return cb(null, txp);
    });
  };


  /**
   * Start an address scanning process.
   * When finished, the scanning process will send a notification 'ScanFinished' to all copayers.
   *
   * @param {Object} opts
   * @param {Boolean} opts.includeCopayerBranches (defaults to false)
   * @param {Callback} cb
   */
  public startScan(opts, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.isComplete());

    const args = {
      includeCopayerBranches: opts.includeCopayerBranches,
    };

    this._doPostRequest('/v1/addresses/scan', args, function(err) {
      return cb(err);
    });
  }

  /**
   * Adds access to the current copayer
   * @param {Object} opts
   * @param {bool} opts.generateNewKey Optional: generate a new key for the new access
   * @param {string} opts.restrictions
   *    - cannotProposeTXs
   *    - cannotXXX TODO
   * @param {string} opts.name  (name for the new access)
   *
   * return the accesses Wallet and the requestPrivateKey
   */
  public addAccess(opts, cb) {
    //TODO
    //$.checkState(this.credentials && this.credentials.canSign());

    opts = opts || {};

    const reqPrivKey = new Bitcore.PrivateKey(opts.generateNewKey ? null : this.credentials.requestPrivKey);
    const requestPubKey = reqPrivKey.toPublicKey().toString();

    const xPriv = new Bitcore.HDPrivateKey(this.credentials.xPrivKey)
      .deriveChild(this.credentials.getBaseAddressDerivationPath());
    const sig = this._Utils.signRequestPubKey(requestPubKey, xPriv);
    const copayerId = this.credentials.copayerId;

    const encCopayerName = opts.name ? this._Utils.encryptMessage(opts.name, this.credentials.sharedEncryptingKey) : null;

    opts = {
      copayerId: copayerId,
      requestPubKey: requestPubKey,
      signature: sig,
      name: encCopayerName,
      restrictions: opts.restrictions,
    };

    this._doPutRequest('/v1/copayers/' + copayerId + '/', opts, (err, res) => {
      if (err) return cb(err);
      return cb(null, res.wallet, reqPrivKey);
    });
  }

  /**
   * Get a note associated with the specified txid
   * @param {Object} opts
   * @param {string} opts.txid - The txid to associate this note with
   */
  public getTxNote(opts, cb) {
    //TODO
    //$.checkState(this.credentials);

    opts = opts || {};
    this._doGetRequest('/v1/txnotes/' + opts.txid + '/', (err, note) => {
      if (err) return cb(err);
      this._processTxNotes(note);
      return cb(null, note);
    });
  }

  /**
   * Edit a note associated with the specified txid
   * @param {Object} opts
   * @param {string} opts.txid - The txid to associate this note with
   * @param {string} opts.body - The contents of the note
   */
  public editTxNote(opts, cb) {
    //TODO
    //$.checkState(this.credentials);

    opts = opts || {};
    if (opts.body) {
      opts.body = this._encryptMessage(opts.body, this.credentials.sharedEncryptingKey);
    }
    this._doPutRequest('/v1/txnotes/' + opts.txid + '/', opts, (err, note) => {
      if (err) return cb(err);
      this._processTxNotes(note);
      return cb(null, note);
    });
  }

  /**
   * Get all notes edited after the specified date
   * @param {Object} opts
   * @param {string} opts.minTs - The starting timestamp
   */
  public getTxNotes(opts, cb) {
    //TODO
    //$.checkState(this.credentials);

    opts = opts || {};
    let args = [];
    if (_.isNumber(opts.minTs)) {
      args.push('minTs=' + opts.minTs);
    }
    var qs = '';
    if (args.length > 0) {
      qs = '?' + args.join('&');
    }

    this._doGetRequest('/v1/txnotes/' + qs, (err, notes) => {
      if (err) return cb(err);
      this._processTxNotes(notes);
      return cb(null, notes);
    });
  }

  /**
   * Returns exchange rate for the specified currency & timestamp.
   * @param {Object} opts
   * @param {string} opts.code - Currency ISO code.
   * @param {Date} [opts.ts] - A timestamp to base the rate on (default Date.now()).
   * @param {String} [opts.provider] - A provider of exchange rates (default 'BitPay').
   * @returns {Object} rates - The exchange rate.
   */
  public getFiatRate(opts, cb) {
    //TODO
    //$.checkArgument(cb);

    opts = opts || {};

    let args = [];
    if (opts.ts) args.push('ts=' + opts.ts);
    if (opts.provider) args.push('provider=' + opts.provider);
    let qs = '';
    if (args.length > 0) {
      qs = '?' + args.join('&');
    }

    this._doGetRequest('/v1/fiatrates/' + opts.code + '/' + qs, (err, rates) => {
      if (err) return cb(err);
      return cb(null, rates);
    });
  }

  /**
   * Subscribe to push notifications.
   * @param {Object} opts
   * @param {String} opts.type - Device type (ios or android).
   * @param {String} opts.token - Device token.
   * @returns {Object} response - Status of subscription.
   */
  public pushNotificationsSubscribe(opts, cb) {
    const url = '/v1/pushnotifications/subscriptions/';
    this._doPostRequest(url, opts, (err, response) => {
      if (err) return cb(err);
      return cb(null, response);
    });
  }

  /**
   * Unsubscribe from push notifications.
   * @param {String} token - Device token
   * @return {Callback} cb - Return error if exists
   */
  public pushNotificationsUnsubscribe(token, cb) {
    const url = '/v2/pushnotifications/subscriptions/' + token;
    this._doDeleteRequest(url, cb);
  }

  /**
   * Listen to a tx for its first confirmation.
   * @param {Object} opts
   * @param {String} opts.txid - The txid to subscribe to.
   * @returns {Object} response - Status of subscription.
   */
  public txConfirmationSubscribe(opts, cb) {
    const url = '/v1/txconfirmations/';
    this._doPostRequest(url, opts, (err, response) => {
      if (err) return cb(err);
      return cb(null, response);
    });
  }

  /**
   * Stop listening for a tx confirmation.
   * @param {String} txid - The txid to unsubscribe from.
   * @return {Callback} cb - Return error if exists
   */
  public txConfirmationUnsubscribe(txid, cb) {
    const url = '/v1/txconfirmations/' + txid;
    this._doDeleteRequest(url, cb);
  }

  /**
   * Returns send max information.
   * @param {String} opts
   * @param {number} opts.feeLevel[='normal'] - Optional. Specify the fee level ('priority', 'normal', 'economy', 'superEconomy').
   * @param {number} opts.feePerKb - Optional. Specify the fee per KB (in satoshi).
   * @param {Boolean} opts.excludeUnconfirmedUtxos - Indicates it if should use (or not) the unconfirmed utxos
   * @param {Boolean} opts.returnInputs - Indicates it if should return (or not) the inputs
   * @return {Callback} cb - Return error (if exists) and object result
   */
  public getSendMaxInfo(opts, cb) {
    let args = [];
    opts = opts || {};

    if (opts.feeLevel) args.push('feeLevel=' + opts.feeLevel);
    if (opts.feePerKb != null) args.push('feePerKb=' + opts.feePerKb);
    if (opts.excludeUnconfirmedUtxos) args.push('excludeUnconfirmedUtxos=1');
    if (opts.returnInputs) args.push('returnInputs=1');

    let qs = '';

    if (args.length > 0)
      qs = '?' + args.join('&');

    const url = '/v1/sendmaxinfo/' + qs;

    this._doGetRequest(url, (err, result) => {
      if (err) return cb(err);
      return cb(null, result);
    });
  }

  /**
   * Get wallet status based on a string identifier (one of: walletId, address, txid)
   *
   * @param {string} opts.identifier - The identifier
   * @param {Boolean} opts.twoStep[=false] - Optional: use 2-step balance computation for improved performance
   * @param {Boolean} opts.includeExtendedInfo (optional: query extended status)
   * @returns {Callback} cb - Returns error or an object with status information
   */
  public getStatusByIdentifier(opts, cb) {
    //TODO
    //$.checkState(this.credentials);

    opts = opts || {};

    let qs = [];
    qs.push('includeExtendedInfo=' + (opts.includeExtendedInfo ? '1' : '0'));
    qs.push('twoStep=' + (opts.twoStep ? '1' : '0'));

    this._doGetRequest('/v1/wallets/' + opts.identifier + '?' + qs.join('&'), (err, result) => {
      if (err || !result || !result.wallet) return cb(err);
      if (result.wallet.status == 'pending') {
        var c = this.credentials;
        result.wallet.secret = this._buildSecret(c.walletId, c.walletPrivKey, c.coin, c.network);
      }

      this._processStatus(result);

      return cb(err, result);
    });
  }


  /*
   *
   * Compatibility Functions
   *
   */

  public _oldCopayDecrypt(username, password, blob) {
    const SEP1 = '@#$';
    const SEP2 = '%^#@';

    let decrypted;
    let passphrase;
    try {
      passphrase = username + SEP1 + password;
      decrypted = sjcl.decrypt(passphrase, blob);
    } catch (e) {
      passphrase = username + SEP2 + password;
      try {
        decrypted = sjcl.decrypt(passphrase, blob);
      } catch (e) {
        //TODO
        //log.debug(e);
      };
    }

    if (!decrypted)
      return null;

    var ret;
    try {
      ret = JSON.parse(decrypted);
    } catch (e) {};
    return ret;
  }


  public getWalletIdsFromOldCopay(username, password, blob) {
    const p = this._oldCopayDecrypt(username, password, blob);
    if (!p) return null;
    const ids = p.walletIds.concat(_.keys(p.focusedTimestamps));
    return _.uniq(ids);
  }


  /**
   * createWalletFromOldCopay
   *
   * @param username
   * @param password
   * @param blob
   * @param cb
   * @return {undefined}
   */
  public createWalletFromOldCopay(username, password, blob, cb) {
    const w = this._oldCopayDecrypt(username, password, blob);
    if (!w) return cb(new Error('Could not decrypt'));

    if (w.publicKeyRing.copayersExtPubKeys.length != w.opts.totalCopayers)
      return cb(new Error('Wallet is incomplete, cannot be imported'));

    this.credentials = this._Credentials.fromOldCopayWallet(w);
    this.recreateWallet(cb);
  }
}
