/** @namespace Verifier */

var $ = require('preconditions').singleton();
var _ = require('lodash');

var Bitcore = require('bitcore-lib');

var Common = require('./common');
var Utils = Common.Utils;

var log = require('./log');

/**
 * @desc Verifier constructor. Checks data given by the server
 *
 * @constructor
 */
function Verifier(opts) {};

/**
 * Check address
 *
 * @param {Function} credentials
 * @param {String} address
 * @returns {Boolean} true or false
 */
Verifier.checkAddress = function(credentials, address) {
  $.checkState(credentials.isComplete());

  var local = Utils.deriveAddress(address.type || credentials.addressType, credentials.publicKeyRing, address.path, credentials.m, credentials.network);
  return (local.address == address.address &&
    _.difference(local.publicKeys, address.publicKeys).length === 0);
};

/**
 * Check copayers
 *
 * @param {Function} credentials
 * @param {Array} copayers
 * @returns {Boolean} true or false
 */
Verifier.checkCopayers = function(credentials, copayers) {
  $.checkState(credentials.walletPrivKey);
  var walletPubKey = Bitcore.PrivateKey.fromString(credentials.walletPrivKey).toPublicKey().toString();

  if (copayers.length != credentials.n) {
    log.error('Missing public keys in server response');
    return false;
  }

  // Repeated xpub kes?
  var uniq = [];
  var error;
  _.each(copayers, function(copayer) {
    if (error) return;

    if (uniq[copayers.xPubKey]++) {
      log.error('Repeated public keys in server response');
      error = true;
    }

    // Not signed pub keys
    if (!copayer.name || !copayer.xPubKey || !copayer.requestPubKey || !copayer.signature) {
      log.error('Missing copayer fields in server response');
      error = true;
    } else {
      var hash = Utils.getCopayerHash(copayer.name, copayer.xPubKey, copayer.requestPubKey);
      if (!Utils.verifyMessage(hash, copayer.signature, walletPubKey)) {
        log.error('Invalid signatures in server response');
        error = true;
      }
    }
  });

  if (error) return false;

  if (!_.contains(_.pluck(copayers, 'xPubKey'), credentials.xPubKey)) {
    log.error('Server response does not contains our public keys')
    return false;
  }
  return true;
};

Verifier.checkProposalCreation = function(args, txp) {
  function strEqual(str1, str2) {
    return ((!str1 && !str2) || (str1 === str2));
  }

  if (txp.outputs.length != args.outputs.length) return false;

  _.each(txp.outputs, function(o1, i) {
    var o2 = args.outputs[i];
    if (!strEqual(o1.toAddress, o2.toAddress)) return false;
    if (!strEqual(o1.script, o2.script)) return false;
    if (o1.amount != o2.amount) return false;
    if (!strEqual(o1.message, o2.message)) return false;
  });

  if (_.isNumber(args.feePerKb) && (txp.feePerKb != args.feePerKb)) return false;
  if (!strEqual(txp.payProUrl, args.payProUrl)) return false;
  if (!strEqual(txp.message, args.message)) return false;
  if (!strEqual(txp.customData, args.customData)) return false;

  return true;
};

Verifier.checkTxProposalSignature = function(credentials, txp) {
  $.checkArgument(txp.creatorId);
  $.checkState(credentials.isComplete());

  var creatorKeys = _.find(credentials.publicKeyRing, function(item) {
    if (Utils.xPubToCopayerId(item.xPubKey) === txp.creatorId) return true;
  });

  if (!creatorKeys) return false;
  var creatorSigningPubKey;

  // If the txp using a selfsigned pub key?
  if (txp.proposalSignaturePubKey) {

    // Verify it...
    if (!Utils.verifyRequestPubKey(txp.proposalSignaturePubKey, txp.proposalSignaturePubKeySig, creatorKeys.xPubKey))
      return false;

    creatorSigningPubKey = txp.proposalSignaturePubKey;
  } else {
    creatorSigningPubKey = creatorKeys.requestPubKey;
  }
  if (!creatorSigningPubKey) return false;


  var hash;
  if (parseInt(txp.version) >= 3) {
    var t = Utils.buildTx(txp);
    hash = t.uncheckedSerialize();
  } else {
    if (txp.outputs) {
      var outputs = _.map(txp.outputs, function(o) {
        return {
          toAddress: o.toAddress,
          amount: o.amount,
          message: o.encryptedMessage || o.message || null
        };
      });
      var proposalHeader = {
        outputs: outputs,
        message: txp.encryptedMessage || txp.message || null,
        payProUrl: txp.payProUrl || null,
      };
      hash = Utils.getProposalHash(proposalHeader);
    } else {
      hash = Utils.getProposalHash(txp.toAddress, txp.amount, txp.encryptedMessage || txp.message || null, txp.payProUrl || null);
    }
  }

  log.debug('Regenerating & verifying tx proposal hash -> Hash: ', hash, ' Signature: ', txp.proposalSignature);
  if (!Utils.verifyMessage(hash, txp.proposalSignature, creatorSigningPubKey))
    return false;

  if (!Verifier.checkAddress(credentials, txp.changeAddress))
    return false;

  return true;
};



/**
 * Check transaction proposal
 *
 * @param {Function} credentials
 * @param {Object} txp
 * @param {Object} Optional: paypro
 * @param {Boolean} isLegit
 */
Verifier.checkTxProposal = function(credentials, txp, opts) {
  opts = opts || {};

  if (!this.checkTxProposalSignature(credentials, txp))
    return false;

  if (opts.paypro) {
    if (txp.outputs[0].toAddress != opts.paypro.toAddress || txp.amount != opts.paypro.amount)
      return false;
  }

  return true;
};

module.exports = Verifier;
