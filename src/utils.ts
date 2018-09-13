import * as _ from 'lodash';
import * as sjcl from 'sjcl';
import * as b from 'buffer';
import * as Stringify from 'json-stable-stringify';

import * as Bitcore from 'bitcore-lib';
import * as BitcoreCash from 'bitcore-lib-cash';

import { Constants } from './common/constants';
import { Defaults } from './common/defaults';

const Bitcore_ = {
  btc: Bitcore,
  bch: BitcoreCash
};

const PrivateKey = Bitcore.PrivateKey;
const PublicKey = Bitcore.PublicKey;
const crypto = Bitcore.crypto;
const encoding = Bitcore.encoding;

let SJCL: Function = ()=>{};

/**
 * Sign Public Key using an Extended Private Key
 * @param requestPubKey   Public Key
 * @param xPrivKey        Extended Private Key
 * @return                Signed Public Key
 */
export function signRequestPubKey(requestPubKey: string, xPrivKey: string): string {
  const priv = new Bitcore.HDPrivateKey(xPrivKey).deriveChild(Constants.PATHS.REQUEST_KEY_AUTH).privateKey;
  return signMessage(requestPubKey, priv);
}

/**
 * Format amount in Satoshis to BTC/BCH
 * @param satoshis    Amount in Satoshis
 * @param unit        Unit you want to get
 * @param opts        Optional<fullPrecision, thousandsSeparator, decimalSeparator>
 * @return            Formated amount
 */
export function formatAmount(satoshis: number, unit: string, opts?: any): string {
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

/**
 * Build a Transaction
 * @param txp    Transaction Proposal
 * @return       Transaction
 */
export function buildTx(txp) {
  const coin = txp.coin || 'btc';

  const bitcore = Bitcore_[coin];

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
        //console.log('Output should have either toAddress or script specified');  
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

/**
 * Derive to Address
 * @param scripType         P2PKH
 * @param publicKeyRing     BIP44 or BIP48
 * @param path              m/1/0 for testnet
 * @param m                 Required signatures
 * @param network           livenet or testnet
 * @param coin              btc or bch
 * @return                  Object<address,path,publicKeys>
 */
export function deriveAddress(scriptType: string, publicKeyRing: string, path: string, m: string, network: string, coin: string) {
  if (!_.includes(_.values(Constants.SCRIPT_TYPES), scriptType)) return;

  coin = coin || 'btc';
  const bitcore = Bitcore_[coin];
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

/**
 * Get Hash for Copayer
 * @param name            Copayer name
 * @param xPubKey         Extended Public Key
 * @param requestPubKey   Request Public Key
 * @return                Hash for Copayer name, Extended Public Key and Request Public Key
 */
export function getCopayerHash(name: string, xPubKey: string, requestPubKey: string): string {
  return [name, xPubKey, requestPubKey].join('|');
}

/**
 * Verify message by signature
 * @param text          Text to be verified
 * @param signature     Your signature
 * @param pubKey        Your Public Key
 * @return              Return true for verified and false for unverified
 */
export function verifyMessage(text: string, signature: string, pubKey: string): boolean {
  const pub = new PublicKey(pubKey);
  const hash = hashMessage(text);

  try {
    const sig = new crypto.Signature.fromString(signature);
    return crypto.ECDSA.verify(hash, sig, pub, 'little');
  } catch (e) {
    return false;
  };
}

/**
 * Decrypt a message
 * @param cyphertextJson  Text to cypher in JSON
 * @param encryptingKey   Key to encrypt (or password)
 * @return                Decrypted message
 */
export function decryptMessage(cyphertextJson: string, encryptingKey: string): string {
  const key = sjcl.codec.base64.toBits(encryptingKey);
  try { 
    return sjcl.decrypt(key, cyphertextJson);
  } catch (e) {
    throw e;
  };
}

/**
 * Extended Public Key to Copayer ID
 * @param coin      btc or bch
 * @param xpub      Extended Public Key
 * @return          Get Copayer ID
 */
export function xPubToCopayerId(coin: string, xpub: string): string {
  const str = coin == 'btc' ? xpub : coin + xpub;
  const hash = sjcl.hash.sha256.hash(str);
  return sjcl.codec.hex.fromBits(hash);
}

/**
 * Verify Request Public Key
 * @param requestPubKey     Request Public Key
 * @param signature         Your signature
 * @param xPubKey           Your Extended Public Key
 * @return                  If verified returns true, else false
 */
export function verifyRequestPubKey(requestPubKey, signature, xPubKey) {
  const pub = (new Bitcore.HDPublicKey(xPubKey)).deriveChild(Constants.PATHS.REQUEST_KEY_AUTH).publicKey;
  return verifyMessage(requestPubKey, signature, pub.toString());
}

/**
 * Return a hashed message
 * @param text      Text to be hashed
 * @return          Hashed message as Buffer
 */
export function hashMessage(text: string) {
  // TODO: It would be nice to be compatible with bitcoind signmessage. How the hash is calculated there?
  const buf = b.Buffer.from(text);
  let ret = crypto.Hash.sha256sha256(buf); // TODO: review crypto
  return new Bitcore.encoding.BufferReader(ret).readReverse();
}

/**
 * Sign a message
 * @param text      Text to be signed
 * @param privKey   Your Private Key
 * @return          Signed message
 */
export function signMessage(text: string, privKey: string): string {
  const priv = new PrivateKey(privKey);
  var hash = hashMessage(text);
  return crypto.ECDSA.sign(hash, priv, 'little').toString();
}

/**
 * Encrypt a message
 * @param message         Message to be encrypted
 * @param encryptingKey   Password
 * @return                Encrypted message
 */
export function encryptMessage(message: string, encryptingKey: string): string {
  const key = sjcl.codec.base64.toBits(encryptingKey);
  return sjcl.encrypt(key, message, _.defaults({
    ks: 128,
    iter: 1,
  }, SJCL));
}

/**
 * Decrypt a message without Throw Error
 * @param cyphertextJson    Message encrypted to be decrypted
 * @param encryptingKey     Password
 * @return                  Decrypted message or string (No Throw)
 */
export function decryptMessageNoThrow(cyphertextJson: string, encryptingKey: string): string {
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
    return decryptMessage(cyphertextJson, encryptingKey);
  } catch (e) {
    return '<ECANNOTDECRYPT>';
  }
}

/**
 * Hash for Transaction Proposal
 * @param proposalHeader    Proposal header
 * @return                  Proposal hash (String)
 */
export function getProposalHash(toAddress: any, amount?: number, message?: any, payProUrl?: string): string {
  function getOldHash(toAddress, amount, message, payProUrl) {
    return [toAddress, amount, (message || ''), (payProUrl || '')].join('|');
  };

  // For backwards compatibility
  if (arguments.length > 1) {
    return getOldHash.apply(this, arguments);
  }

  return Stringify(toAddress);
}

/**
 * Convert a Private Key To AES Key
 * @param privKey     Private Key
 * @return            AES Key
 */
export function privateKeyToAESKey(privKey: string) {
  if (!Bitcore.PrivateKey.isValid(privKey)) {
    //console.log('The private key received is invalid');
    return;
  }
  const pk = Bitcore.PrivateKey.fromString(privKey);
  return Bitcore.crypto.Hash.sha256(pk.toBuffer()).slice(0, 16).toString('base64');
}
