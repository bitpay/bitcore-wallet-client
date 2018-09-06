import * as _ from 'lodash';

import * as Bitcore from 'bitcore-lib';

import { Utils } from './common/utils';

//import * as log from './log';

export class Verifier {

  private utils;

  constructor() {
    this.utils = new Utils();
    console.log('Verifier class ready!');
  }

  /**
   * Check address
   *
   * @param {Function} credentials
   * @param {String} address
   * @returns {Boolean} true or false
   */
  public checkAddress(credentials, address) {
    // preconditions
    if (!credentials.isComplete()) return;

    const local = this.utils.deriveAddress(address.type || credentials.addressType, credentials.publicKeyRing, address.path, credentials.m, credentials.network, credentials.coin);
    return (local.address == address.address &&
      _.difference(local.publicKeys, address.publicKeys).length === 0);
  }

  /**
   * Check copayers
   *
   * @param {Function} credentials
   * @param {Array} copayers
   * @returns {Boolean} true or false
   */
  public checkCopayers(credentials, copayers) {
    // TODO preconditions
    if (!credentials.walletPrivKey) return;
    const walletPubKey = Bitcore.PrivateKey.fromString(credentials.walletPrivKey).toPublicKey().toString();

    if (copayers.length != credentials.n) {
      // TODO log.error('Missing public keys in server response');
      return false;
    }

    // Repeated xpub kes?
    let uniq = [];
    let error;
    _.each(copayers, function(copayer) {
      if (error) return;

      if (uniq[copayers.xPubKey]++) {
        // TODO log.error('Repeated public keys in server response');
        error = true;
      }

      // Not signed pub keys
      if (!(copayer.encryptedName || copayer.name) || !copayer.xPubKey || !copayer.requestPubKey || !copayer.signature) {
        // TODO log.error('Missing copayer fields in server response');
        error = true;
      } else {
        const hash = this.utils.getCopayerHash(copayer.encryptedName || copayer.name, copayer.xPubKey, copayer.requestPubKey);
        if (!this.utils.verifyMessage(hash, copayer.signature, walletPubKey)) {
          // TODO log.error('Invalid signatures in server response');
          error = true;
        }
      }
    });

    if (error) return false;

    if (!_.includes(_.map(copayers, 'xPubKey'), credentials.xPubKey)) {
      // TODO log.error('Server response does not contains our public keys')
      return false;
    }
    return true;
  }

  public checkProposalCreation(args, txp, encryptingKey) {
    function strEqual(str1, str2) {
      return ((!str1 && !str2) || (str1 === str2));
    }

    if (txp.outputs.length != args.outputs.length) return false;

    for (var i = 0; i < txp.outputs.length; i++) {
      let o1 = txp.outputs[i];
      let o2 = args.outputs[i];
      if (!strEqual(o1.toAddress, o2.toAddress)) return false;
      if (!strEqual(o1.script, o2.script)) return false;
      if (o1.amount != o2.amount) return false;
      let decryptedMessage = null;
      try {
        decryptedMessage = this.utils.decryptMessage(o2.message, encryptingKey);
      } catch (e) {
        return false;
      }
      if (!strEqual(o1.message, decryptedMessage)) return false;
    }

    let changeAddress;
    if (txp.changeAddress) {
      changeAddress = txp.changeAddress.address;
    }

    if (args.changeAddress && !strEqual(changeAddress, args.changeAddress)) return false;
    if (_.isNumber(args.feePerKb) && (txp.feePerKb != args.feePerKb)) return false;
    if (!strEqual(txp.payProUrl, args.payProUrl)) return false;

    let decryptedMessage = null;
    try {
      decryptedMessage = this.utils.decryptMessage(args.message, encryptingKey);
    } catch (e) {
      return false;
    }
    if (!strEqual(txp.message, decryptedMessage)) return false;
    if (args.customData && !_.isEqual(txp.customData, args.customData)) return false;

    return true;
  }

  public checkTxProposalSignature(credentials, txp) {
    // TODO preconditions
    if (!txp.creatorId) return;
    // TODO preconditions
    if (!credentials.isComplete()) return;

    const creatorKeys = _.find(credentials.publicKeyRing, function(item) {
      if (this.utils.xPubToCopayerId(txp.coin || 'btc', item.xPubKey) === txp.creatorId) return true;
    });

    if (!creatorKeys) return false;
    let creatorSigningPubKey;

    // If the txp using a selfsigned pub key?
    if (txp.proposalSignaturePubKey) {

      // Verify it...
      if (!this.utils.verifyRequestPubKey(txp.proposalSignaturePubKey, txp.proposalSignaturePubKeySig, creatorKeys.xPubKey))
        return false;

      creatorSigningPubKey = txp.proposalSignaturePubKey;
    } else {
      creatorSigningPubKey = creatorKeys.requestPubKey;
    }
    if (!creatorSigningPubKey) return false;


    let hash;
    if (parseInt(txp.version) >= 3) {
      var t = this.utils.buildTx(txp);
      hash = t.uncheckedSerialize();
    } else {
      throw new Error('Transaction proposal not supported');
    }

    // TODO log.debug('Regenerating & verifying tx proposal hash -> Hash: ', hash, ' Signature: ', txp.proposalSignature);
    if (!this.utils.verifyMessage(hash, txp.proposalSignature, creatorSigningPubKey))
      return false;

    if (!this.checkAddress(credentials, txp.changeAddress))
      return false;

    return true;
  }


  public checkPaypro(txp, payproOpts) {
    let toAddress, amount, feeRate;

    if (parseInt(txp.version) >= 3) {
      toAddress = txp.outputs[0].toAddress;
      amount = txp.amount;
      if (txp.feePerKb) {
        feeRate = txp.feePerKb / 1024;
      }
    } else {
      toAddress = txp.toAddress;
      amount = txp.amount;
    }

    //  if (feeRate && payproOpts.requiredFeeRate &&
    //      feeRate < payproOpts.requiredFeeRate)
    //  return false;

    return toAddress == payproOpts.toAddress && amount == payproOpts.amount;
  };


  /**
   * Check transaction proposal
   *
   * @param {Function} credentials
   * @param {Object} txp
   * @param {Object} Optional: paypro
   * @param {Boolean} isLegit
   */
  public checkTxProposal(credentials, txp, opts) {
    opts = opts || {};

    if (!this.checkTxProposalSignature(credentials, txp))
      return false;

    if (opts.paypro && !this.checkPaypro(txp, opts.paypro))
      return false;

    return true;
  }
}
