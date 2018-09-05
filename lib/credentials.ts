import * as _ from 'lodash';
import * as sjcl from 'sjcl';


import * as Bitcore from 'bitcore-lib';
import * as Mnemonic from 'bitcore-mnemonic';

import { Constants } from './common/constants';
import { Utils } from './common/utils';

const FIELDS = [
  'coin',
  'network',
  'xPrivKey',
  'xPrivKeyEncrypted',
  'xPubKey',
  'requestPrivKey',
  'requestPubKey',
  'copayerId',
  'publicKeyRing',
  'walletId',
  'walletName',
  'm',
  'n',
  'walletPrivKey',
  'personalEncryptingKey',
  'sharedEncryptingKey',
  'copayerName',
  'externalSource',
  'mnemonic',
  'mnemonicEncrypted',
  'entropySource',
  'mnemonicHasPassphrase',
  'derivationStrategy',
  'account',
  'compliantDerivation',
  'addressType',
  'hwInfo',
  'entropySourcePath',
];

const wordsForLang = {
  'en': Mnemonic.Words.ENGLISH,
  'es': Mnemonic.Words.SPANISH,
  'ja': Mnemonic.Words.JAPANESE,
  'zh': Mnemonic.Words.CHINESE,
  'fr': Mnemonic.Words.FRENCH,
  'it': Mnemonic.Words.ITALIAN,
};

export class Credentials {

  private version;
  private derivationStrategy;
  private account;
  private coin;
  private network;
  private xPrivKey;
  private compliantDerivation;
  private expand;
  private mnemonic;
  private mnemonicHasPassphrase;
  private entropySourcePath;
  private xPubKey;
  private entropySource;
  private externalSource;
  private requestPrivKey;
  private requestPubKey;
  private personalEncryptingKey;
  private copayerId;
  private publicKeyRing;
  private addressType;
  private xPrivKeyEncrypted;
  private walletPrivKey;
  private sharedEncryptingKey;
  private walletId;
  private walletName;
  private m;
  private n;
  private copayerName;
  private mnemonicEncrypted;

  private utils;

  constructor() {
    this.utils = new Utils();
    this.version = '1.0.0';
    this.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP44;
    this.account = 0;
  }

  private _checkCoin(coin) {
    if (!_.includes(['btc', 'bch'], coin)) throw new Error('Invalid coin');
  }

  private _checkNetwork(network) {
    if (!_.includes(['livenet', 'testnet'], network)) throw new Error('Invalid network');
  }

  public create(coin, network) {
    this._checkCoin(coin);
    this._checkNetwork(network);

    let x = new Credentials();

    x.coin = coin;
    x.network = network;
    x.xPrivKey = (new Bitcore.HDPrivateKey(network)).toString();
    x.compliantDerivation = true;
    x.expand = this._expand();
    return x;
  }

  public createWithMnemonic(coin, network, passphrase, language, account, opts) {
    this._checkCoin(coin);
    this._checkNetwork(network);
    if (!wordsForLang[language]) throw new Error('Unsupported language');
    // TODO: $.shouldBeNumber(account);

    opts = opts || {};

    let m = new Mnemonic(wordsForLang[language]);
    while (!Mnemonic.isValid(m.toString())) {
      m = new Mnemonic(wordsForLang[language])
    };
    let x = new Credentials();

    x.coin = coin;
    x.network = network;
    x.account = account;
    x.xPrivKey = m.toHDPrivateKey(passphrase, network).toString();
    x.compliantDerivation = true;
    x.expand = this._expand();
    x.mnemonic = m.phrase;
    x.mnemonicHasPassphrase = !!passphrase;

    return x;
  }

  public fromExtendedPrivateKey(coin, xPrivKey, account, derivationStrategy, opts) {
    this._checkCoin(coin);
    //TODO: $.shouldBeNumber(account);
    //TODO: $.checkArgument(_.includes(_.values(Constants.DERIVATION_STRATEGIES), derivationStrategy));

    opts = opts || {};

    let x = new Credentials();
    x.coin = coin;
    x.xPrivKey = xPrivKey;
    x.account = account;
    x.derivationStrategy = derivationStrategy;
    x.compliantDerivation = !opts.nonCompliantDerivation;

    if (opts.walletPrivKey) {
      x.addWalletPrivateKey(opts.walletPrivKey);
    }

    x.expand = this._expand();
    return x;
  }

  // note that mnemonic / passphrase is NOT stored
  public fromMnemonic(coin, network, words, passphrase, account, derivationStrategy, opts) {
    this._checkCoin(coin);
    this._checkNetwork(network);
    //TODO: $.shouldBeNumber(account);
    //TODO: $.checkArgument(_.includes(_.values(Constants.DERIVATION_STRATEGIES), derivationStrategy));

    opts = opts || {};

    let m = new Mnemonic(words);
    let x = new Credentials();
    x.coin = coin;
    x.xPrivKey = m.toHDPrivateKey(passphrase, network).toString();
    x.mnemonic = words;
    x.mnemonicHasPassphrase = !!passphrase;
    x.account = account;
    x.derivationStrategy = derivationStrategy;
    x.compliantDerivation = !opts.nonCompliantDerivation;
    x.entropySourcePath = opts.entropySourcePath;

    if (opts.walletPrivKey) {
      x.addWalletPrivateKey(opts.walletPrivKey);
    }

    x.expand = this._expand();
    return x;
  }

  /*
   * BWC uses
   * xPrivKey -> m/44'/network'/account' -> Base Address Key
   * so, xPubKey is PublicKeyHD(xPrivKey.deriveChild("m/44'/network'/account'").
   *
   * For external sources, this derivation should be done before
   * call fromExtendedPublicKey
   *
   * entropySource should be a HEX string containing pseudo-random data, that can
   * be deterministically derived from the xPrivKey, and should not be derived from xPubKey
   */
  public fromExtendedPublicKey(coin, xPubKey, source, entropySourceHex, account, derivationStrategy, opts) {
    this._checkCoin(coin);
    //TODO: $.checkArgument(entropySourceHex);
    //TODO: $.shouldBeNumber(account);
    //TODO: $.checkArgument(_.includes(_.values(Constants.DERIVATION_STRATEGIES), derivationStrategy));

    opts = opts || {};

    const entropyBuffer = new Buffer(entropySourceHex, 'hex');
    //require at least 112 bits of entropy
    //TODO: $.checkArgument(entropyBuffer.length >= 14, 'At least 112 bits of entropy are needed')

    let x = new Credentials();
    x.coin = coin;
    x.xPubKey = xPubKey;
    x.entropySource = Bitcore.crypto.Hash.sha256sha256(entropyBuffer).toString('hex');
    x.account = account;
    x.derivationStrategy = derivationStrategy;
    x.externalSource = source;
    x.compliantDerivation = true;
    x.expand = this._expand();
    return x;
  }

  // Get network from extended private key or extended public key
  public _getNetworkFromExtendedKey(xKey) {
    //TODO: $.checkArgument(xKey && _.isString(xKey));
    return xKey.charAt(0) == 't' ? 'testnet' : 'livenet';
  }

  public _hashFromEntropy(prefix, length) {
    //TODO: $.checkState(prefix);
    const b = new Buffer(this.entropySource, 'hex');
    const b2 = Bitcore.crypto.Hash.sha256hmac(b, new Buffer(prefix));
    return b2.slice(0, length);
  }


  public _expand() {
    // TODO precondition
    //$.checkState(this.xPrivKey || (this.xPubKey && this.entropySource));


    const network = this._getNetworkFromExtendedKey(this.xPrivKey || this.xPubKey);
    if (this.network) {
      // TODO precondition
      //$.checkState(this.network == network);
    } else {
      this.network = network;
    }

    let xPrivKey;
    let deriveFn;

    if (this.xPrivKey) {
      xPrivKey = new Bitcore.HDPrivateKey.fromString(this.xPrivKey);

      deriveFn = this.compliantDerivation ? _.bind(xPrivKey.deriveChild, xPrivKey) : _.bind(xPrivKey.deriveNonCompliantChild, xPrivKey);

      const derivedXPrivKey = deriveFn(this.getBaseAddressDerivationPath());

      // this is the xPubKey shared with the server.
      this.xPubKey = derivedXPrivKey.hdPublicKey.toString();
    }

    // requests keys from mnemonics, but using a xPubkey
    // This is only used when importing mnemonics FROM 
    // an hwwallet, in which xPriv was not available when
    // the wallet was created.
    if (this.entropySourcePath) {
      const seed = deriveFn(this.entropySourcePath).publicKey.toBuffer();
      this.entropySource = Bitcore.crypto.Hash.sha256sha256(seed).toString('hex');
    }

    if (this.entropySource) {
      // request keys from entropy (hw wallets)
      var seed = this._hashFromEntropy('reqPrivKey', 32);
      var privKey = new Bitcore.PrivateKey(seed.toString('hex'), network);
      this.requestPrivKey = privKey.toString();
      this.requestPubKey = privKey.toPublicKey().toString();
    } else {
      // request keys derived from xPriv
      var requestDerivation = deriveFn(Constants.PATHS.REQUEST_KEY);
      this.requestPrivKey = requestDerivation.privateKey.toString();

      var pubKey = requestDerivation.publicKey;
      this.requestPubKey = pubKey.toString();

      this.entropySource = Bitcore.crypto.Hash.sha256(requestDerivation.privateKey.toBuffer()).toString('hex');
    }

    this.personalEncryptingKey = this._hashFromEntropy('personalKey', 16).toString('base64');

    //TODO $.checkState(this.coin);

    this.copayerId = this.utils.xPubToCopayerId(this.coin, this.xPubKey);
    this.publicKeyRing = [{
      xPubKey: this.xPubKey,
      requestPubKey: this.requestPubKey,
    }];
  }

  public fromObj(obj) {
    var x = new Credentials();

    _.each(FIELDS, function(k) {
      x[k] = obj[k];
    });

    x.coin = x.coin || 'btc';
    x.derivationStrategy = x.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP45;
    x.addressType = x.addressType || Constants.SCRIPT_TYPES.P2SH;
    x.account = x.account || 0;

    //TODO $.checkState(x.xPrivKey || x.xPubKey || x.xPrivKeyEncrypted, "invalid input");
    return x;
  }

  public toObj() {
    var self = this;

    var x = {};
    _.each(FIELDS, function(k) {
      x[k] = self[k];
    });
    return x;
  }

  public getBaseAddressDerivationPath() {
    let purpose;
    switch (this.derivationStrategy) {
      case Constants.DERIVATION_STRATEGIES.BIP45:
        return "m/45'";
      case Constants.DERIVATION_STRATEGIES.BIP44:
        purpose = '44';
        break;
      case Constants.DERIVATION_STRATEGIES.BIP48:
        purpose = '48';
        break;
    }

    const coin = (this.network == 'livenet' ? "0" : "1");
    return "m/" + purpose + "'/" + coin + "'/" + this.account + "'";
  }

  public getDerivedXPrivKey(password) {
    const path = this.getBaseAddressDerivationPath();
    const xPrivKey = new Bitcore.HDPrivateKey(this.getKeys(password)['xPrivKey'], this.network);
    const deriveFn = !!this.compliantDerivation ? _.bind(xPrivKey.deriveChild, xPrivKey) : _.bind(xPrivKey.deriveNonCompliantChild, xPrivKey);
    return deriveFn(path);
  }

  public addWalletPrivateKey(walletPrivKey) {
    this.walletPrivKey = walletPrivKey;
    this.sharedEncryptingKey = this.utils.privateKeyToAESKey(walletPrivKey);
  }

  public addWalletInfo(walletId, walletName, m, n, copayerName) {
    this.walletId = walletId;
    this.walletName = walletName;
    this.m = m;
    this.n = n;

    if (copayerName)
      this.copayerName = copayerName;

    if (this.derivationStrategy == 'BIP44' && n == 1)
      this.addressType = Constants.SCRIPT_TYPES.P2PKH;
    else
      this.addressType = Constants.SCRIPT_TYPES.P2SH;

    // Use m/48' for multisig hardware wallets
    if (!this.xPrivKey && this.externalSource && n > 1) {
      this.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP48;
    }

    if (n == 1) {
      this.addPublicKeyRing([{
        xPubKey: this.xPubKey,
        requestPubKey: this.requestPubKey,
      }]);
    }
  }

  public hasWalletInfo() {
    return !!this.walletId;
  }

  public isPrivKeyEncrypted() {
    return (!!this.xPrivKeyEncrypted) && !this.xPrivKey;
  };

  public encryptPrivateKey(password, opts) {
    if (this.xPrivKeyEncrypted)
      throw new Error('Private key already encrypted');

    if (!this.xPrivKey)
      throw new Error('No private key to encrypt');


    this.xPrivKeyEncrypted = sjcl.encrypt(password, this.xPrivKey, opts);
    if (!this.xPrivKeyEncrypted)
      throw new Error('Could not encrypt');

    if (this.mnemonic)
      this.mnemonicEncrypted = sjcl.encrypt(password, this.mnemonic, opts);

    delete this.xPrivKey;
    delete this.mnemonic;
  };

  public decryptPrivateKey(password) {
    if (!this.xPrivKeyEncrypted)
      throw new Error('Private key is not encrypted');

    try {
      this.xPrivKey = sjcl.decrypt(password, this.xPrivKeyEncrypted);

      if (this.mnemonicEncrypted) {
        this.mnemonic = sjcl.decrypt(password, this.mnemonicEncrypted);
      }
      delete this.xPrivKeyEncrypted;
      delete this.mnemonicEncrypted;
    } catch (ex) {
      throw new Error('Could not decrypt');
    }
  }

  public getKeys(password) {
    let keys = {};

    if (this.isPrivKeyEncrypted()) {
      //TODO $.checkArgument(password, 'Private keys are encrypted, a password is needed');
      try {
        keys['xPrivKey'] = sjcl.decrypt(password, this.xPrivKeyEncrypted);

        if (this.mnemonicEncrypted) {
          keys['mnemonic'] = sjcl.decrypt(password, this.mnemonicEncrypted);
        }
      } catch (ex) {
        throw new Error('Could not decrypt');
      }
    } else {
      keys['xPrivKey'] = this.xPrivKey;
      keys['mnemonic'] = this.mnemonic;
    }
    return keys;
  }

  public addPublicKeyRing = function(publicKeyRing) {
    this.publicKeyRing = _.clone(publicKeyRing);
  }

  public canSign() {
    return (!!this.xPrivKey || !!this.xPrivKeyEncrypted);
  }

  public setNoSign() {
    delete this.xPrivKey;
    delete this.xPrivKeyEncrypted;
    delete this.mnemonic;
    delete this.mnemonicEncrypted;
  }

  public isComplete() {
    if (!this.m || !this.n) return false;
    if (!this.publicKeyRing || this.publicKeyRing.length != this.n) return false;
    return true;
  }

  public hasExternalSource() {
    return (typeof this.externalSource == "string");
  }

  public getExternalSourceName() {
    return this.externalSource;
  }

  public getMnemonic() {
    if (this.mnemonicEncrypted && !this.mnemonic) {
      throw new Error('Credentials are encrypted');
    }
    return this.mnemonic;
  }

  public clearMnemonic = function() {
    delete this.mnemonic;
    delete this.mnemonicEncrypted;
  }

  public fromOldCopayWallet(w) {
    let walletPrivKeyFromOldCopayWallet = function(w) {
      // IN BWS, the master Pub Keys are not sent to the server, 
      // so it is safe to use them as seed for wallet's shared secret.
      const seed = w.publicKeyRing.copayersExtPubKeys.sort().join('');
      const seedBuf = new Buffer(seed);
      const privKey = new Bitcore.PrivateKey.fromBuffer(Bitcore.crypto.Hash.sha256(seedBuf));
      return privKey.toString();
    };

    let credentials = new Credentials();
    credentials.coin = 'btc';
    credentials.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP45;
    credentials.xPrivKey = w.privateKey.extendedPrivateKeyString;
    credentials.expand = this._expand();

    credentials.addWalletPrivateKey(walletPrivKeyFromOldCopayWallet(w));
    credentials.addWalletInfo(w.opts.id, w.opts.name, w.opts.requiredCopayers, w.opts.totalCopayers, '');

    let pkr = _.map(w.publicKeyRing.copayersExtPubKeys, function(xPubStr) {

      const isMe = xPubStr === credentials.xPubKey;
      let requestDerivation;

      if (isMe) {
        const path = Constants.PATHS.REQUEST_KEY;
        requestDerivation = (new Bitcore.HDPrivateKey(credentials.xPrivKey))
          .deriveChild(path).hdPublicKey;
      } else {
        // this 
        const path = Constants.PATHS.REQUEST_KEY_AUTH;
        requestDerivation = (new Bitcore.HDPublicKey(xPubStr)).deriveChild(path);
      }

      // Grab Copayer Name
      let hd = new Bitcore.HDPublicKey(xPubStr).deriveChild('m/2147483646/0/0');
      let pubKey = hd.publicKey.toString('hex');
      let copayerName = w.publicKeyRing.nicknameFor[pubKey];
      if (isMe) {
        credentials.copayerName = copayerName;
      }

      return {
        xPubKey: xPubStr,
        requestPubKey: requestDerivation.publicKey.toString(),
        copayerName: copayerName,
      };
    });
    credentials.addPublicKeyRing(pkr);
    return credentials;
  }
}

