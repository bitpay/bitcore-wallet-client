import * as _ from 'lodash';

import * as Bitcore from 'bitcore-lib';
let Bitcore_ = {
  btc: Bitcore,
  bch: require('bitcore-lib-cash'),
};

let BitcorePayPro = require('bitcore-payment-protocol');
let BWS = require('bitcore-wallet-service');

import { Utils } from '../lib/common/utils';
import { Client } from '../lib/client';
import { Constants } from '../lib/common/constants';

let ExpressApp = BWS.ExpressApp;
let Storage = BWS.Storage;

// Required for testing
import { expect } from 'chai';
import 'mocha';
import * as request from 'supertest';
let tingodb = require('tingodb')().Db;

var helpers = {
  'toSatoshi': null,
  'newClient': null,
  'newDb': null,
  'generateUtxos': null
};

helpers.toSatoshi = function(btc) {
  if (_.isArray(btc)) {
    return _.map(btc, helpers.toSatoshi);
  } else {
    return parseFloat((btc * 1e8).toPrecision(12));
  }
};

helpers.newClient = function(app) {
  return new Client({
    baseUrl: '/bws/api',
    request: request(app),
  });
};

helpers.newDb = function() {
  this.dbCounter = (this.dbCounter || 0) + 1;
  return new tingodb('./db/test' + this.dbCounter, {});
};

helpers.generateUtxos = function(scriptType, publicKeyRing, path, requiredSignatures, amounts) {
  amounts = [].concat(amounts);
  var utxos = _.map(amounts, function(amount, i) {
    let _Utils = new Utils();

    var address = _Utils.deriveAddress(scriptType, publicKeyRing, path, requiredSignatures, 'testnet', 'btc');

    var scriptPubKey;
    switch (scriptType) {
      case Constants.SCRIPT_TYPES.P2SH:
        scriptPubKey = Bitcore.Script.buildMultisigOut(address.publicKeys, requiredSignatures).toScriptHashOut();
        break;
      case Constants.SCRIPT_TYPES.P2PKH:
        scriptPubKey = Bitcore.Script.buildPublicKeyHashOut(address.address);
        break;
    }
    expect(scriptPubKey).to.exist;

    var obj = {
      txid: Bitcore.crypto.Hash.sha256(new Buffer(i)).toString('hex'),
      vout: 100,
      satoshis: helpers.toSatoshi(amount),
      scriptPubKey: scriptPubKey.toBuffer().toString('hex'),
      address: address.address,
      path: path,
      publicKeys: address.publicKeys,
    };
    return obj;
  });
  return utxos;
};

var blockchainExplorerMock = {
  'reset': null,
  'utxos': [],
  'txHistory': [],
  'feeLevels': null
};

blockchainExplorerMock.reset = function() {
  blockchainExplorerMock.utxos = [];
  blockchainExplorerMock.txHistory = [];
  blockchainExplorerMock.feeLevels = [];
};

describe('Client API', () => {

  var clients, app, sandbox;
  var i = 0;
  beforeEach(function(done) {
    var storage = new Storage({
      db: helpers.newDb(),
    });
    var expressApp = new ExpressApp();
    expressApp.start({
        ignoreRateLimiter: true,
        storage: storage,
        blockchainExplorer: blockchainExplorerMock,
        disableLogs: true,
      },
      function() {
        app = expressApp.app;

        // Generates 5 clients
        clients = _.map(_.range(5), function(i) {
          return helpers.newClient(app);
        });
        blockchainExplorerMock.reset();
        /*sandbox = sinon.sandbox.create();

        if (!process.env.BWC_SHOW_LOGS) {
          sandbox.stub(log, 'warn');
          sandbox.stub(log, 'info');
          sandbox.stub(log, 'error');
        }*/
        done();
      });
  });
  afterEach(function(done) {
    //sandbox.restore();
    done();
  });

  it('should be an instance of Client', () => {
    const c = new Client({
      baseUrl: '/bws/api',
      request: request(app)
    });
    expect(c).to.be.an.instanceof(Client);
  });

  describe('Build & sign txs', function() {
    var masterPrivateKey = 'tprv8ZgxMBicQKsPd8U9aBBJ5J2v8XMwKwZvf8qcu2gLK5FRrsrPeSgkEcNHqKx4zwv6cP536m68q2UD7wVM24zdSCpaJRmpowaeJTeVMXL5v5k';
    var derivedPrivateKey = {
      'BIP44': new Bitcore.HDPrivateKey(masterPrivateKey).deriveChild("m/44'/1'/0'").toString(),
      'BIP45': new Bitcore.HDPrivateKey(masterPrivateKey).deriveChild("m/45'").toString(),
      'BIP48': new Bitcore.HDPrivateKey(masterPrivateKey).deriveChild("m/48'/1'/0'").toString(),
    };

    describe('#buildTx', function() {
      it('Raw tx roundtrip', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1000, 2000]);
        var txp = {
          version: '2.0.0',
          inputs: utxos,
          toAddress: toAddress,
          amount: 1200,
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1],
          fee: 10050,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        var t = new Client({}).getRawTx(txp);
        expect(t).to.exist;
        expect(t).to.be.a('string');
        expect(/^[\da-f]+$/.test(t)).to.be.true;

        var t2 = new Bitcore.Transaction(t);
        expect(t2.inputs.length).to.equal(2);
        expect(t2.outputs.length).to.equal(2);
        expect(t2.outputs[0].satoshis).to.equal(1200);
      });
      
      it('should build a tx correctly (BIP44)', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1000, 2000]);
        var txp = {
          version: '2.0.0',
          inputs: utxos,
          toAddress: toAddress,
          amount: 1200,
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1],
          fee: 10050,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        let _Utils = new Utils();
        var t = _Utils.buildTx(txp);
        var bitcoreError = t.getSerializationError({
          disableIsFullySigned: true,
          disableSmallFees: true,
          disableLargeFees: true,
        });

        expect(bitcoreError).to.be.undefined;
        expect(t.getFee()).to.equal(10050);
      });

      it('should build a tx correctly (BIP48)', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey['BIP48']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1000, 2000]);
        var txp = {
          version: '2.0.0',
          inputs: utxos,
          toAddress: toAddress,
          amount: 1200,
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1],
          fee: 10050,
          derivationStrategy: 'BIP48',
          addressType: 'P2PKH',
        };
        let _Utils = new Utils();
        var t = _Utils.buildTx(txp);
        var bitcoreError = t.getSerializationError({
          disableIsFullySigned: true,
          disableSmallFees: true,
          disableLargeFees: true,
        });

        expect(bitcoreError).to.be.undefined;
        expect(t.getFee()).to.equal(10050);
      });
    });
  });
});
