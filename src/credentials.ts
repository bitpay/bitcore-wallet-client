import * as _ from 'lodash';
import * as sjcl from 'sjcl';


import * as Bitcore from 'bitcore-lib';
import * as Mnemonic from 'bitcore-mnemonic';

import { Constants } from './common/constants';
import { 
  xPubToCopayerId,
  privateKeyToAESKey
} from './utils';

interface Key {
  xPrivKey?: string,
  mnemonic?: string
};

interface Credential {
  account: number;
  version: string;
  derivationStrategy: string;
  coin?: string;
  network?: string;
  xPrivKey?: string;
  xPrivKeyEncrypted?: string;
  xPubKey?: string;
  requestPrivKey?: string;
  requestPubKey?: string;
  copayerId?: string;
  publicKeyRing?: Array<any>;
  walletId?: number;
  walletName?: string;
  m?: number;
  n?: number;
  walletPrivKey?: string;
  personalEncryptingKey?: string;
  sharedEncryptingKey?: string;
  copayerName?: string;
  externalSource?: string;
  mnemonic?: string;
  mnemonicEncrypted?: string;
  entropySource?: string;
  mnemonicHasPassphrase?: boolean;
  compliantDerivation?: boolean;
  addressType?: string;
  hwInfo?: string;
  entropySourcePath?: string;
};

const WORDS_FOR_LANGUAGE = {
  'en': Mnemonic.Words.ENGLISH,
  'es': Mnemonic.Words.SPANISH,
  'ja': Mnemonic.Words.JAPANESE,
  'zh': Mnemonic.Words.CHINESE,
  'fr': Mnemonic.Words.FRENCH,
  'it': Mnemonic.Words.ITALIAN,
};

const AVAILABLE_COINS = [
  'btc', 
  'bch'
];

const AVAILABLE_NETWORKS = [
  'livenet',
  'testnet'
];

export class Credentials {

  public credential: Credential = {
    version: '1', 
    account: 0, 
    derivationStrategy: Constants.DERIVATION_STRATEGIES.BIP44
  };

  constructor() {}

  /**
   * Check valid coin
   * @param   {string}  Coin
   * @return  {void}
   */
  private checkCoin(coin: string): void {
    if (!_.includes(AVAILABLE_COINS, coin)) throw new Error('Invalid coin');
  }

  /**
   * Check valid network
   * @param   {string}  Network
   * @return  {void}
   */
  private checkNetwork(network: string): void {
    if (!_.includes(AVAILABLE_NETWORKS, network)) throw new Error('Invalid network');
  }

  /**
   * Check valid language
   * @param   {string}  Language
   * @return  {void}
   */
  private checkLanguage(language: string): void {
    if (!WORDS_FOR_LANGUAGE[language]) throw new Error('Unsupported language');
  }

  /**
   * Check valid Derivation Strategy
   * @param   {string}  Derivation Strategy
   * @return  {void}
   */
  private checkDerivationStrategy(derivationStrategy: string): void {
    if (!_.includes(_.values(Constants.DERIVATION_STRATEGIES), derivationStrategy)) throw new Error('Unknown Derivation Strategy');
  }

  /**
   * Check Entropy Buffer
   * @param   {string}  Derivation Strategy
   * @return  {void}
   */
  private checkEntropyBuffer(entropyBuffer: any): void {
    //require at least 112 bits of entropy
    if (entropyBuffer.length < 14) throw new Error('At least 112 bits of entropy are needed');
  }

  /**
   * Create a new credential
   * @param   {string}      Coin
   * @param   {string}      Network
   * @return  {credential}  Credential
   */
  public create(coin: string, network: string): Credential {
    this.checkCoin(coin);
    this.checkNetwork(network);

    this.credential.coin = coin;
    this.credential.network = network;
    this.credential.xPrivKey = (new Bitcore.HDPrivateKey(network)).toString();
    this.credential.compliantDerivation = true;
    this.expand();
    return this.credential;
  }

  /**
   * Create a new credential with Mnemonic
   * @param   {string}        Coin
   * @param   {string}        Network
   * @param   {string}        Passphrase
   * @param   {string}        Language
   * @param   {number}        Account
   * @param   {any}           Opts
   * @return  {credential}    Credential
   */
  public createWithMnemonic(coin: string, network: string, passphrase: string, language: string, account: number, opts?: any): Credential {
    this.checkCoin(coin);
    this.checkNetwork(network);
    this.checkLanguage(language);
    
    opts = opts || {};

    let m = new Mnemonic(WORDS_FOR_LANGUAGE[language]);
    while (!Mnemonic.isValid(m.toString())) {
      m = new Mnemonic(WORDS_FOR_LANGUAGE[language])
    };

    this.credential.coin = coin;
    this.credential.network = network;
    this.credential.account = account;
    this.credential.xPrivKey = m.toHDPrivateKey(passphrase, network).toString();
    this.credential.compliantDerivation = true;
    this.credential.mnemonic = m.phrase;
    this.credential.mnemonicHasPassphrase = !!passphrase;
    this.expand();

    return this.credential;
  }

  /**
   * Create a credential from Extended Private Key
   * @param   {String}      Coin
   * @param   {String}      Extended Private Key
   * @param   {Number}      Account
   * @param   {String}      Derivation Strategy
   * @param   {Any}         Opts
   * @return  {Credential}  Credential
   */
  public fromExtendedPrivateKey(coin: string, xPrivKey: string, account: number, derivationStrategy: string, opts?: any): Credential {
    this.checkCoin(coin);
    this.checkDerivationStrategy(derivationStrategy);

    opts = opts || {};

    this.credential.coin = coin;
    this.credential.xPrivKey = xPrivKey;
    this.credential.account = account;
    this.credential.derivationStrategy = derivationStrategy;
    this.credential.compliantDerivation = !opts.nonCompliantDerivation;

    if (opts.walletPrivKey) {
      this.addWalletPrivateKey(opts.walletPrivKey);
    }

    this.expand();
    return this.credential;
  }

  /**
   * Create credential from Mnemonic (note that mnemonic / passphrase is NOT stored)
   * @param   {string}        Coin
   * @param   {string}        Network
   * @param   {string}        Words
   * @param   {string}        Passphrase
   * @param   {number}        Account
   * @param   {string}        Derivation Strategy
   * @param   {any}           Options
   * @return  {credential}    Credential
   */
  public fromMnemonic(coin: string, network: string, words: string, passphrase: string, account: number, derivationStrategy: string, opts?: any): Credential {
    this.checkCoin(coin);
    this.checkNetwork(network);
    this.checkDerivationStrategy(derivationStrategy);

    opts = opts || {};

    let m = new Mnemonic(words);
    this.credential.coin = coin;
    this.credential.xPrivKey = m.toHDPrivateKey(passphrase, network).toString();
    this.credential.mnemonic = words;
    this.credential.mnemonicHasPassphrase = !!passphrase;
    this.credential.account = account;
    this.credential.derivationStrategy = derivationStrategy;
    this.credential.compliantDerivation = !opts.nonCompliantDerivation;
    this.credential.entropySourcePath = opts.entropySourcePath;

    if (opts.walletPrivKey) {
      this.addWalletPrivateKey(opts.walletPrivKey);
    }

    this.expand();
    return this.credential;
  }

  /**
   * BWC uses
   * xPrivKey -> m/44'/network'/account' -> Base Address Key
   * so, xPubKey is PublicKeyHD(xPrivKey.deriveChild("m/44'/network'/account'").
   *
   * For external sources, this derivation should be done before
   * call fromExtendedPublicKey
   *
   * entropySource should be a HEX string containing pseudo-random data, that can
   * be deterministically derived from the xPrivKey, and should not be derived from xPubKey
   *
   * @param   {string}      Coin
   * @param   {string}      Extended Private Key
   * @param   {string}      Source
   * @param   {string}      Entropy Source Hexadecimal
   * @param   {number}      Accouont
   * @param   {string}      Derivation Strategy
   * @param   {any}         Opts
   * @return  {credential}  Credential
   */
  public fromExtendedPublicKey(coin: string, xPubKey: string, source: string, entropySourceHex: string, account: number, derivationStrategy: string, opts?: any): Credential {
    this.checkCoin(coin);
    this.checkDerivationStrategy(derivationStrategy);

    opts = opts || {};

    const entropyBuffer = new Buffer(entropySourceHex, 'hex');
    this.checkEntropyBuffer(entropyBuffer);

    this.credential.coin = coin;
    this.credential.xPubKey = xPubKey;
    this.credential.entropySource = Bitcore.crypto.Hash.sha256sha256(entropyBuffer).toString('hex');
    this.credential.account = account;
    this.credential.derivationStrategy = derivationStrategy;
    this.credential.externalSource = source;
    this.credential.compliantDerivation = true;
    this.expand();
    return this.credential;
  }

  /**
   * Get network from extended private key or extended public key
   * @param   {string}   xKey
   * @return  {string}   Network
   */
  private getNetworkFromExtendedKey(xKey:string): string {
    return xKey.charAt(0) == 't' ? 'testnet' : 'livenet';
  }

  /**
   * Get hash from entropy
   * @param   {string}    Prefix
   * @param   {number}    Length
   * @return  {string}    Network
   */
  private hashFromEntropy(prefix: string, length?: number): any {
    length = length || 16;
    const b = new Buffer(this.credential.entropySource, 'hex');
    const b2 = Bitcore.crypto.Hash.sha256hmac(b, new Buffer(prefix));
    return b2.slice(0, length);
  }

  /**
   * Complete credential (expand)
   * @return {void}
   */
  private expand(): void {
    // TODO precondition
    //$.checkState(this.xPrivKey || (this.xPubKey && this.entropySource));

    const network = this.getNetworkFromExtendedKey(this.credential.xPrivKey || this.credential.xPubKey);
    if (this.credential.network) {
      // TODO precondition
      //$.checkState(this.network == network);
      //if (this.credential.network != network) throw new Error('Network should not be different');
    } else {
      this.credential.network = network;
    }

    let xPrivKey;
    let deriveFn;

    if (this.credential.xPrivKey) {
      xPrivKey = new Bitcore.HDPrivateKey.fromString(this.credential.xPrivKey);

      deriveFn = this.credential.compliantDerivation ? _.bind(xPrivKey.deriveChild, xPrivKey) : _.bind(xPrivKey.deriveNonCompliantChild, xPrivKey);

      const derivedXPrivKey = deriveFn(this.getBaseAddressDerivationPath());

      // this is the xPubKey shared with the server.
      this.credential.xPubKey = derivedXPrivKey['hdPublicKey'].toString();
    }

    // requests keys from mnemonics, but using a xPubkey
    // This is only used when importing mnemonics FROM 
    // an hwwallet, in which xPriv was not available when
    // the wallet was created.
    if (this.credential.entropySourcePath) {
      const seed = deriveFn(this.credential.entropySourcePath).publicKey.toBuffer();
      this.credential.entropySource = Bitcore.crypto.Hash.sha256sha256(seed).toString('hex');
    }

    if (this.credential.entropySource) {
      // request keys from entropy (hw wallets)
      const seed = this.hashFromEntropy('reqPrivKey', 32);
      const privKey = new Bitcore.PrivateKey(seed.toString('hex'), network);
      this.credential.requestPrivKey = privKey.toString();
      this.credential.requestPubKey = privKey.toPublicKey().toString();
    } else {
      // request keys derived from xPriv
      const requestDerivation = deriveFn(Constants.PATHS.REQUEST_KEY);
      this.credential.requestPrivKey = requestDerivation.privateKey.toString();

      const pubKey = requestDerivation.publicKey;
      this.credential.requestPubKey = pubKey.toString();

      this.credential.entropySource = Bitcore.crypto.Hash.sha256(requestDerivation.privateKey.toBuffer()).toString('hex');
    }

    this.credential.personalEncryptingKey = this.hashFromEntropy('personalKey', 16).toString('base64');

    this.credential.copayerId = xPubToCopayerId(this.credential.coin, this.credential.xPubKey);
    this.credential.publicKeyRing = [{
      xPubKey: this.credential.xPubKey,
      requestPubKey: this.credential.requestPubKey,
    }];
  }

  /**
   * Create credential from object
   * @param   {object}        Object
   * @return  {credential}    Credential
   */
  public fromObj(obj: any): Credential {
    _.assign(this.credential, obj);

    this.credential.coin = this.credential.coin || 'btc';
    this.credential.derivationStrategy = this.credential.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP45;
    this.credential.addressType = this.credential.addressType || Constants.SCRIPT_TYPES.P2SH;
    this.credential.account = this.credential.account || 0;

    //TODO $.checkState(x.xPrivKey || x.xPubKey || x.xPrivKeyEncrypted, "invalid input");
    if (!this.credential.xPrivKey && !this.credential.xPubKey && !this.credential.xPrivKeyEncrypted)
      throw new Error('Invalid input');
    return this.credential;
  }

  /**
   * Export credential
   * @return {credential}   Credential
   */
  public toObj(): Credential {
    return this.credential;
  }

  /**
   * Get address derivation path
   * @return {string} Derivation Path
   */
  public getBaseAddressDerivationPath(): string {
    let purpose;
    switch (this.credential.derivationStrategy) {
      case Constants.DERIVATION_STRATEGIES.BIP45:
        return "m/45'";
      case Constants.DERIVATION_STRATEGIES.BIP44:
        purpose = '44';
        break;
      case Constants.DERIVATION_STRATEGIES.BIP48:
        purpose = '48';
        break;
    }

    const coin = (this.credential.network == 'livenet' ? "0" : "1");
    return "m/" + purpose + "'/" + coin + "'/" + this.credential.account + "'";
  }

  /**
   * Get Derived Extended Private Key
   * @param   {string}    Password
   * @return  {string}    Derivation Path
   */
  public getDerivedXPrivKey(password?: string): any {
    const path = this.getBaseAddressDerivationPath();
    const xPrivKey = new Bitcore.HDPrivateKey(this.getKeys(password).xPrivKey, this.credential.network);
    const deriveFn = !!this.credential.compliantDerivation ? _.bind(xPrivKey.deriveChild, xPrivKey) : _.bind(xPrivKey.deriveNonCompliantChild, xPrivKey);
    return deriveFn(path);
  }

  /**
   * Add a Wallet Private Key
   * @param   {string}    Wallet Private Key
   * @return  {void}
   */
  private addWalletPrivateKey(walletPrivKey: string): void {
    this.credential.walletPrivKey = walletPrivKey;
    this.credential.sharedEncryptingKey = privateKeyToAESKey(walletPrivKey);
  }

  /**
   * Add a Wallet Information
   * @param   {number}    Wallet ID
   * @param   {string}    Wallet Name
   * @param   {number}    M (required signatures)
   * @param   {number}    N (total of Copayers)
   * @param   {string}    Copayer Name
   * @param   {string}    Wallet Private Key
   * @return  {void}
   */
  public addWalletInfo(walletId: number, walletName: string, m: number, n: number, copayerName?: string): void {
    this.credential.walletId = walletId;
    this.credential.walletName = walletName;
    this.credential.m = m;
    this.credential.n = n;

    if (copayerName)
      this.credential.copayerName = copayerName;

    if (this.credential.derivationStrategy == 'BIP44' && n == 1)
      this.credential.addressType = Constants.SCRIPT_TYPES.P2PKH;
    else
      this.credential.addressType = Constants.SCRIPT_TYPES.P2SH;

    // Use m/48' for multisig hardware wallets
    if (!this.credential.xPrivKey && this.credential.externalSource && n > 1) {
      this.credential.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP48;
    }

    if (n == 1) {
      this.addPublicKeyRing([{
        xPubKey: this.credential.xPubKey,
        requestPubKey: this.credential.requestPubKey,
      }]);
    }
  }

  /**
   * Check if Wallet has information
   * @return {boolean} True or False
   */
  public hasWalletInfo(): boolean {
    return !!this.credential.walletId;
  }

  /**
   * Check if Private Key is Encrypted
   * @return {boolean} True or False
   */
  public isPrivKeyEncrypted(): boolean {
    return (!!this.credential.xPrivKeyEncrypted) && !this.credential.xPrivKey;
  }

  /**
   * Encrypt Private Key
   * @param   {string}  Password
   * @return  {void}
   */
  public encryptPrivateKey(password: string, opts?: any): void {
    if (this.credential.xPrivKeyEncrypted)
      throw new Error('Private key already encrypted');

    if (!this.credential.xPrivKey)
      throw new Error('No private key to encrypt');


    this.credential.xPrivKeyEncrypted = sjcl.encrypt(password, this.credential.xPrivKey, opts);
    if (!this.credential.xPrivKeyEncrypted)
      throw new Error('Could not encrypt');

    if (this.credential.mnemonic)
      this.credential.mnemonicEncrypted = sjcl.encrypt(password, this.credential.mnemonic, opts);

    delete this.credential.xPrivKey;
    delete this.credential.mnemonic;
  }

  /**
   * Decrypt Private Key
   * @param   {string}  Password
   * @return  {void}
   */
  public decryptPrivateKey(password: string): void {
    if (!this.credential.xPrivKeyEncrypted)
      throw new Error('Private key is not encrypted');

    try {
      this.credential.xPrivKey = sjcl.decrypt(password, this.credential.xPrivKeyEncrypted);

      if (this.credential.mnemonicEncrypted) {
        this.credential.mnemonic = sjcl.decrypt(password, this.credential.mnemonicEncrypted);
      }
      delete this.credential.xPrivKeyEncrypted;
      delete this.credential.mnemonicEncrypted;
    } catch (_) {
      throw new Error('Could not decrypt');
    }
  }

  /**
   * Get Keys
   * @param   {string}  Password
   * @return  {key}     Key
   */
  public getKeys(password?: string): Key {
    let keys: Key = {};

    if (this.isPrivKeyEncrypted()) {
      if (!password) throw new Error('Private keys are encrypted, a password is needed');
      try {
        keys.xPrivKey = sjcl.decrypt(password, this.credential.xPrivKeyEncrypted);

        if (this.credential.mnemonicEncrypted) {
          keys.mnemonic = sjcl.decrypt(password, this.credential.mnemonicEncrypted);
        }
      } catch (_) {
        throw new Error('Could not decrypt');
      }
    } else {
      keys.xPrivKey = this.credential.xPrivKey;
      keys.mnemonic = this.credential.mnemonic;
    }
    return keys;
  }

  /**
   * Add Public Key Ring
   * @param   {string}  Public Key Ring
   * @return  {void}
   */
  public addPublicKeyRing(publicKeyRing: Array<any>): void {
    this.credential.publicKeyRing = _.clone(publicKeyRing);
  }

  /**
   * Check if can sign
   * @return {boolean}  True or False
   */
  public canSign(): boolean {
    return (!!this.credential.xPrivKey || !!this.credential.xPrivKeyEncrypted);
  }

  /**
   * Set no Signature
   * @return {void}
   */
  public setNoSign(): void {
    delete this.credential.xPrivKey;
    delete this.credential.xPrivKeyEncrypted;
    delete this.credential.mnemonic;
    delete this.credential.mnemonicEncrypted;
  }

  /**
   * Check if it is complete
   * @return {boolean}  True or False
   */
  public isComplete(): boolean {
    if (!this.credential.m || !this.credential.n) return false;
    if (!this.credential.publicKeyRing || this.credential.publicKeyRing.length != this.credential.n) return false;
    return true;
  }

  /**
   * Check if it has external source
   * @return {boolean}  True or False
   */
  public hasExternalSource(): boolean {
    return !!(typeof this.credential.externalSource == "string");
  }

  /**
   * Get External Source Name
   * @return {string}  External Source Name
   */
  public getExternalSourceName(): string {
    return this.credential.externalSource;
  }

  /**
   * Get Mnemonic
   * @return {string}  Mnemonic
   */
  public getMnemonic(): string {
    if (this.credential.mnemonicEncrypted && !this.credential.mnemonic) 
      throw new Error('Credentials are encrypted');
    return this.credential.mnemonic;
  }

  /**
   * Clear Mnemonic
   * @return {void}
   */
  public clearMnemonic(): void {
    delete this.credential.mnemonic;
    delete this.credential.mnemonicEncrypted;
  }

  /**
   * Create credential from OLD Copay Wallet
   * @param   {any}           Object Wallet
   * @return  {credential}    Credential
   */
  public fromOldCopayWallet(w: any): Credential {
    let walletPrivKeyFromOldCopayWallet = (w) => {
      // IN BWS, the master Pub Keys are not sent to the server, 
      // so it is safe to use them as seed for wallet's shared secret.
      const seed = w.publicKeyRing.copayersExtPubKeys.sort().join('');
      const seedBuf = new Buffer(seed);
      const privKey = new Bitcore.PrivateKey.fromBuffer(Bitcore.crypto.Hash.sha256(seedBuf));
      return privKey.toString();
    };

    this.credential.coin = 'btc';
    this.credential.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP45;
    this.credential.xPrivKey = w.privateKey.extendedPrivateKeyString;
    this.expand();

    this.addWalletPrivateKey(walletPrivKeyFromOldCopayWallet(w));
    this.addWalletInfo(w.opts.id, w.opts.name, w.opts.requiredCopayers, w.opts.totalCopayers, '');

    let pkr = _.map(w.publicKeyRing.copayersExtPubKeys, (xPubStr) => {

      const isMe = xPubStr === this.credential.xPubKey;
      let requestDerivation;

      if (isMe) {
        const path = Constants.PATHS.REQUEST_KEY;
        requestDerivation = (new Bitcore.HDPrivateKey(this.credential.xPrivKey))
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
        this.credential.copayerName = copayerName;
      }

      return {
        xPubKey: xPubStr,
        requestPubKey: requestDerivation.publicKey.toString(),
        copayerName: copayerName,
      };
    });
    this.addPublicKeyRing(pkr);
    return this.credential;
  }
}

