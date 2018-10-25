import * as _ from 'lodash';
import * as sjcl from 'sjcl';

import * as Bitcore from 'bitcore-lib';
import * as Mnemonic from 'bitcore-mnemonic';

import {Constants} from './common/constants';
import {xPubToCopayerId, privateKeyToAESKey} from './utils';

interface Key {
  xPrivKey?: string;
  mnemonic?: string;
}

export interface Credential {
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
}

const WORDS_FOR_LANGUAGE = {
  en: Mnemonic.Words.ENGLISH,
  es: Mnemonic.Words.SPANISH,
  ja: Mnemonic.Words.JAPANESE,
  zh: Mnemonic.Words.CHINESE,
  fr: Mnemonic.Words.FRENCH,
  it: Mnemonic.Words.ITALIAN,
};

const AVAILABLE_COINS = ['btc', 'bch'];

const AVAILABLE_NETWORKS = ['livenet', 'testnet'];

export class Credentials implements Credential {
  account = 0;
  version = '1';
  derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP44;
  coin;
  network;
  xPrivKey;
  xPrivKeyEncrypted;
  xPubKey;
  requestPrivKey;
  requestPubKey;
  copayerId;
  publicKeyRing;
  walletId;
  walletName;
  m;
  n;
  walletPrivKey;
  personalEncryptingKey;
  sharedEncryptingKey;
  copayerName;
  externalSource;
  mnemonic;
  mnemonicEncrypted;
  entropySource;
  mnemonicHasPassphrase;
  compliantDerivation;
  addressType;
  hwInfo;
  entropySourcePath;

  constructor() {}

  /**
   * Get credential
   * @return  {Credential}
   */
  private getCredential(): Credential {
    return {
      account: this.account,
      version: this.version,
      derivationStrategy: this.derivationStrategy,
      coin: this.coin,
      network: this.network,
      xPrivKey: this.xPrivKey,
      xPrivKeyEncrypted: this.xPrivKeyEncrypted,
      xPubKey: this.xPubKey,
      requestPrivKey: this.requestPrivKey,
      requestPubKey: this.requestPubKey,
      copayerId: this.copayerId,
      publicKeyRing: this.publicKeyRing,
      walletId: this.walletId,
      walletName: this.walletName,
      m: this.m,
      n: this.n,
      walletPrivKey: this.walletPrivKey,
      personalEncryptingKey: this.personalEncryptingKey,
      sharedEncryptingKey: this.sharedEncryptingKey,
      copayerName: this.copayerName,
      externalSource: this.externalSource,
      mnemonic: this.mnemonic,
      mnemonicEncrypted: this.mnemonicEncrypted,
      entropySource: this.entropySource,
      mnemonicHasPassphrase: this.mnemonicHasPassphrase,
      compliantDerivation: this.compliantDerivation,
      addressType: this.addressType,
      hwInfo: this.hwInfo,
      entropySourcePath: this.entropySourcePath,
    };
  }

  /**
   * Set credential
   * @return  {Credential}
   */
  private setCredential(c: Credential) {
    this.account = c.account || 0;
    this.version = c.version || '1';
    this.derivationStrategy =
      c.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP45;
    this.coin = c.coin || 'btc';
    this.network = c.network;
    this.xPrivKey = c.xPrivKey;
    this.xPrivKeyEncrypted = c.xPrivKeyEncrypted;
    this.xPubKey = c.xPubKey;
    this.requestPrivKey = c.requestPrivKey;
    this.requestPubKey = c.requestPubKey;
    this.copayerId = c.copayerId;
    this.publicKeyRing = c.publicKeyRing;
    this.walletId = c.walletId;
    this.walletName = c.walletName;
    this.m = c.m;
    this.n = c.n;
    this.walletPrivKey = c.walletPrivKey;
    this.personalEncryptingKey = c.personalEncryptingKey;
    this.sharedEncryptingKey = c.sharedEncryptingKey;
    this.copayerName = c.copayerName;
    this.externalSource = c.externalSource;
    this.mnemonic = c.mnemonic;
    this.mnemonicEncrypted = c.mnemonicEncrypted;
    this.entropySource = c.entropySource;
    this.mnemonicHasPassphrase = c.mnemonicHasPassphrase;
    this.compliantDerivation = c.compliantDerivation;
    this.addressType = c.addressType || Constants.SCRIPT_TYPES.P2SH;
    this.hwInfo = c.hwInfo;
    this.entropySourcePath = c.entropySourcePath;
  }

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
    if (!_.includes(AVAILABLE_NETWORKS, network))
      throw new Error('Invalid network');
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
    if (
      !_.includes(_.values(Constants.DERIVATION_STRATEGIES), derivationStrategy)
    )
      throw new Error('Unknown Derivation Strategy');
  }

  /**
   * Check Entropy Buffer
   * @param   {string}  Derivation Strategy
   * @return  {void}
   */
  private checkEntropyBuffer(entropyBuffer: any): void {
    //require at least 112 bits of entropy
    if (entropyBuffer.length < 14)
      throw new Error('At least 112 bits of entropy are needed');
  }

  /**
   * Create a new credential
   * @param   {string}      Coin
   * @param   {string}      Network
   */
  public create(coin: string, network: string) {
    this.checkCoin(coin);
    this.checkNetwork(network);

    this.coin = coin;
    this.network = network;
    this.xPrivKey = new Bitcore.HDPrivateKey(network).toString();
    this.compliantDerivation = true;
    this.expand();
  }

  /**
   * Create a new credential with Mnemonic
   * @param   {string}        Coin
   * @param   {string}        Network
   * @param   {string}        Passphrase
   * @param   {string}        Language
   * @param   {number}        Account
   * @param   {any}           Opts
   */
  public createWithMnemonic(
    coin: string,
    network: string,
    passphrase: string,
    language: string,
    account: number,
    opts?: any,
  ) {
    this.checkCoin(coin);
    this.checkNetwork(network);
    this.checkLanguage(language);

    opts = opts || {};

    let m = new Mnemonic(WORDS_FOR_LANGUAGE[language]);
    while (!Mnemonic.isValid(m.toString())) {
      m = new Mnemonic(WORDS_FOR_LANGUAGE[language]);
    }

    this.coin = coin;
    this.network = network;
    this.account = account;
    this.xPrivKey = m.toHDPrivateKey(passphrase, network).toString();
    this.compliantDerivation = true;
    this.mnemonic = m.phrase;
    this.mnemonicHasPassphrase = !!passphrase;
    this.expand();
  }

  /**
   * Create a credential from Extended Private Key
   * @param   {String}      Coin
   * @param   {String}      Extended Private Key
   * @param   {Number}      Account
   * @param   {String}      Derivation Strategy
   * @param   {Any}         Opts
   */
  public fromExtendedPrivateKey(
    coin: string,
    xPrivKey: string,
    account: number,
    derivationStrategy: string,
    opts?: any,
  ) {
    this.checkCoin(coin);
    this.checkDerivationStrategy(derivationStrategy);

    opts = opts || {};

    this.coin = coin;
    this.xPrivKey = xPrivKey;
    this.account = account;
    this.derivationStrategy = derivationStrategy;
    this.compliantDerivation = !opts.nonCompliantDerivation;

    if (opts.walletPrivKey) {
      this.addWalletPrivateKey(opts.walletPrivKey);
    }

    this.expand();
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
   */
  public fromMnemonic(
    coin: string,
    network: string,
    words: string,
    passphrase: string,
    account: number,
    derivationStrategy: string,
    opts?: any,
  ) {
    this.checkCoin(coin);
    this.checkNetwork(network);
    this.checkDerivationStrategy(derivationStrategy);

    opts = opts || {};

    let m = new Mnemonic(words);
    this.coin = coin;
    this.xPrivKey = m.toHDPrivateKey(passphrase, network).toString();
    this.mnemonic = words;
    this.mnemonicHasPassphrase = !!passphrase;
    this.account = account;
    this.derivationStrategy = derivationStrategy;
    this.compliantDerivation = !opts.nonCompliantDerivation;
    this.entropySourcePath = opts.entropySourcePath;

    if (opts.walletPrivKey) {
      this.addWalletPrivateKey(opts.walletPrivKey);
    }

    this.expand();
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
   */
  public fromExtendedPublicKey(
    coin: string,
    xPubKey: string,
    source: string,
    entropySourceHex: string,
    account: number,
    derivationStrategy: string,
    opts?: any,
  ) {
    this.checkCoin(coin);
    this.checkDerivationStrategy(derivationStrategy);

    opts = opts || {};

    const entropyBuffer = new Buffer(entropySourceHex, 'hex');
    this.checkEntropyBuffer(entropyBuffer);

    this.coin = coin;
    this.xPubKey = xPubKey;
    this.entropySource = Bitcore.crypto.Hash.sha256sha256(
      entropyBuffer,
    ).toString('hex');
    this.account = account;
    this.derivationStrategy = derivationStrategy;
    this.externalSource = source;
    this.compliantDerivation = true;
    this.expand();
  }

  /**
   * Get network from extended private key or extended public key
   * @param   {string}   xKey
   * @return  {string}   Network
   */
  private getNetworkFromExtendedKey(xKey: string): string {
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
    const b = new Buffer(this.entropySource, 'hex');
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

    const network = this.getNetworkFromExtendedKey(
      this.xPrivKey || this.xPubKey,
    );
    if (this.network) {
      // TODO precondition
      //$.checkState(this.network == network);
      //if (this.credential.network != network) throw new Error('Network should not be different');
    } else {
      this.network = network;
    }

    let xPrivKey;
    let deriveFn;

    if (this.xPrivKey) {
      xPrivKey = new Bitcore.HDPrivateKey.fromString(this.xPrivKey);

      deriveFn = this.compliantDerivation
        ? _.bind(xPrivKey.deriveChild, xPrivKey)
        : _.bind(xPrivKey.deriveNonCompliantChild, xPrivKey);

      const derivedXPrivKey = deriveFn(this.getBaseAddressDerivationPath());

      // this is the xPubKey shared with the server.
      this.xPubKey = derivedXPrivKey['hdPublicKey'].toString();
    }

    // requests keys from mnemonics, but using a xPubkey
    // This is only used when importing mnemonics FROM
    // an hwwallet, in which xPriv was not available when
    // the wallet was created.
    if (this.entropySourcePath) {
      const seed = deriveFn(this.entropySourcePath).publicKey.toBuffer();
      this.entropySource = Bitcore.crypto.Hash.sha256sha256(seed).toString(
        'hex',
      );
    }

    if (this.entropySource) {
      // request keys from entropy (hw wallets)
      const seed = this.hashFromEntropy('reqPrivKey', 32);
      const privKey = new Bitcore.PrivateKey(seed.toString('hex'), network);
      this.requestPrivKey = privKey.toString();
      this.requestPubKey = privKey.toPublicKey().toString();
    } else {
      // request keys derived from xPriv
      const requestDerivation = deriveFn(Constants.PATHS.REQUEST_KEY);
      this.requestPrivKey = requestDerivation.privateKey.toString();

      const pubKey = requestDerivation.publicKey;
      this.requestPubKey = pubKey.toString();

      this.entropySource = Bitcore.crypto.Hash.sha256(
        requestDerivation.privateKey.toBuffer(),
      ).toString('hex');
    }

    this.personalEncryptingKey = this.hashFromEntropy(
      'personalKey',
      16,
    ).toString('base64');

    this.copayerId = xPubToCopayerId(this.coin, this.xPubKey);
    this.publicKeyRing = [
      {
        xPubKey: this.xPubKey,
        requestPubKey: this.requestPubKey,
      },
    ];
  }

  /**
   * Create credential from object
   * @param   {any}        Object
   */
  public fromObj(obj: any) {
    let c: Credential = this.getCredential();
    _.assign(c, obj);

    this.setCredential(c);

    //TODO $.checkState(x.xPrivKey || x.xPubKey || x.xPrivKeyEncrypted, "invalid input");
    if (!this.xPrivKey && !this.xPubKey && !this.xPrivKeyEncrypted)
      throw new Error('Invalid input');
  }

  /**
   * Export credential
   * @return {credential}   Credential
   */
  public toObj(): Credential {
    return this.getCredential();
  }

  /**
   * Get address derivation path
   * @return {string} Derivation Path
   */
  public getBaseAddressDerivationPath(): string {
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

    const coin = this.network == 'livenet' ? '0' : '1';
    return 'm/' + purpose + "'/" + coin + "'/" + this.account + "'";
  }

  /**
   * Get Derived Extended Private Key
   * @param   {string}    Password
   * @return  {string}    Derivation Path
   */
  public getDerivedXPrivKey(password?: string): any {
    const path = this.getBaseAddressDerivationPath();
    const xPrivKey = new Bitcore.HDPrivateKey(
      this.getKeys(password).xPrivKey,
      this.network,
    );
    const deriveFn = !!this.compliantDerivation
      ? _.bind(xPrivKey.deriveChild, xPrivKey)
      : _.bind(xPrivKey.deriveNonCompliantChild, xPrivKey);
    return deriveFn(path);
  }

  /**
   * Add a Wallet Private Key
   * @param   {string}    Wallet Private Key
   * @return  {void}
   */
  public addWalletPrivateKey(walletPrivKey: string): void {
    this.walletPrivKey = walletPrivKey;
    this.sharedEncryptingKey = privateKeyToAESKey(walletPrivKey);
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
  public addWalletInfo(
    walletId: number,
    walletName: string,
    m: number,
    n: number,
    copayerName?: string,
  ): void {
    this.walletId = walletId;
    this.walletName = walletName;
    this.m = m;
    this.n = n;

    if (copayerName) this.copayerName = copayerName;

    if (this.derivationStrategy == 'BIP44' && n == 1)
      this.addressType = Constants.SCRIPT_TYPES.P2PKH;
    else this.addressType = Constants.SCRIPT_TYPES.P2SH;

    // Use m/48' for multisig hardware wallets
    if (!this.xPrivKey && this.externalSource && n > 1) {
      this.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP48;
    }

    if (n == 1) {
      this.addPublicKeyRing([
        {
          xPubKey: this.xPubKey,
          requestPubKey: this.requestPubKey,
        },
      ]);
    }
  }

  /**
   * Check if Wallet has information
   * @return {boolean} True or False
   */
  public hasWalletInfo(): boolean {
    return !!this.walletId;
  }

  /**
   * Check if Private Key is Encrypted
   * @return {boolean} True or False
   */
  public isPrivKeyEncrypted(): boolean {
    return !!this.xPrivKeyEncrypted && !this.xPrivKey;
  }

  /**
   * Encrypt Private Key
   * @param   {string}  Password
   * @return  {void}
   */
  public encryptPrivateKey(password: string, opts?: any): void {
    if (this.xPrivKeyEncrypted)
      throw new Error('Private key already encrypted');

    if (!this.xPrivKey) throw new Error('No private key to encrypt');

    this.xPrivKeyEncrypted = sjcl.encrypt(password, this.xPrivKey, opts);
    if (!this.xPrivKeyEncrypted) throw new Error('Could not encrypt');

    if (this.mnemonic)
      this.mnemonicEncrypted = sjcl.encrypt(password, this.mnemonic, opts);

    delete this.xPrivKey;
    delete this.mnemonic;
  }

  /**
   * Decrypt Private Key
   * @param   {string}  Password
   * @return  {void}
   */
  public decryptPrivateKey(password: string): void {
    if (!this.xPrivKeyEncrypted)
      throw new Error('Private key is not encrypted');

    try {
      this.xPrivKey = sjcl.decrypt(password, this.xPrivKeyEncrypted);

      if (this.mnemonicEncrypted) {
        this.mnemonic = sjcl.decrypt(password, this.mnemonicEncrypted);
      }
      delete this.xPrivKeyEncrypted;
      delete this.mnemonicEncrypted;
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
      if (!password)
        throw new Error('Private keys are encrypted, a password is needed');
      try {
        keys.xPrivKey = sjcl.decrypt(password, this.xPrivKeyEncrypted);

        if (this.mnemonicEncrypted) {
          keys.mnemonic = sjcl.decrypt(password, this.mnemonicEncrypted);
        }
      } catch (_) {
        throw new Error('Could not decrypt');
      }
    } else {
      keys.xPrivKey = this.xPrivKey;
      keys.mnemonic = this.mnemonic;
    }
    return keys;
  }

  /**
   * Add Public Key Ring
   * @param   {string}  Public Key Ring
   * @return  {void}
   */
  public addPublicKeyRing(publicKeyRing: Array<any>): void {
    this.publicKeyRing = _.clone(publicKeyRing);
  }

  /**
   * Check if can sign
   * @return {boolean}  True or False
   */
  public canSign(): boolean {
    return !!this.xPrivKey || !!this.xPrivKeyEncrypted;
  }

  /**
   * Set no Signature
   * @return {void}
   */
  public setNoSign(): void {
    delete this.xPrivKey;
    delete this.xPrivKeyEncrypted;
    delete this.mnemonic;
    delete this.mnemonicEncrypted;
  }

  /**
   * Check if it is complete
   * @return {boolean}  True or False
   */
  public isComplete(): boolean {
    if (!this.m || !this.n) return false;
    if (!this.publicKeyRing || this.publicKeyRing.length != this.n)
      return false;
    return true;
  }

  /**
   * Check if it has external source
   * @return {boolean}  True or False
   */
  public hasExternalSource(): boolean {
    return !!(typeof this.externalSource == 'string');
  }

  /**
   * Get External Source Name
   * @return {string}  External Source Name
   */
  public getExternalSourceName(): string {
    return this.externalSource;
  }

  /**
   * Get Mnemonic
   * @return {string}  Mnemonic
   */
  public getMnemonic(): string {
    if (this.mnemonicEncrypted && !this.mnemonic)
      throw new Error('Credentials are encrypted');
    return this.mnemonic;
  }

  /**
   * Clear Mnemonic
   * @return {void}
   */
  public clearMnemonic(): void {
    delete this.mnemonic;
    delete this.mnemonicEncrypted;
  }

  /**
   * Create credential from OLD Copay Wallet
   * @param   {any}           Object Wallet
   */
  public fromOldCopayWallet(w: any) {
    let walletPrivKeyFromOldCopayWallet = w => {
      // IN BWS, the master Pub Keys are not sent to the server,
      // so it is safe to use them as seed for wallet's shared secret.
      const seed = w.publicKeyRing.copayersExtPubKeys.sort().join('');
      const seedBuf = new Buffer(seed);
      const privKey = new Bitcore.PrivateKey.fromBuffer(
        Bitcore.crypto.Hash.sha256(seedBuf),
      );
      return privKey.toString();
    };

    this.coin = 'btc';
    this.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP45;
    this.xPrivKey = w.privateKey.extendedPrivateKeyString;
    this.expand();

    this.addWalletPrivateKey(walletPrivKeyFromOldCopayWallet(w));
    this.addWalletInfo(
      w.opts.id,
      w.opts.name,
      w.opts.requiredCopayers,
      w.opts.totalCopayers,
      '',
    );

    let pkr = _.map(w.publicKeyRing.copayersExtPubKeys, xPubStr => {
      const isMe = xPubStr === this.xPubKey;
      let requestDerivation;

      if (isMe) {
        const path = Constants.PATHS.REQUEST_KEY;
        requestDerivation = new Bitcore.HDPrivateKey(this.xPrivKey).deriveChild(
          path,
        ).hdPublicKey;
      } else {
        // this
        const path = Constants.PATHS.REQUEST_KEY_AUTH;
        requestDerivation = new Bitcore.HDPublicKey(xPubStr).deriveChild(path);
      }

      // Grab Copayer Name
      let hd = new Bitcore.HDPublicKey(xPubStr).deriveChild('m/2147483646/0/0');
      let pubKey = hd.publicKey.toString('hex');
      let copayerName = w.publicKeyRing.nicknameFor[pubKey];
      if (isMe) {
        this.copayerName = copayerName;
      }

      return {
        xPubKey: xPubStr,
        requestPubKey: requestDerivation.publicKey.toString(),
        copayerName: copayerName,
      };
    });
    this.addPublicKeyRing(pkr);
  }
}
