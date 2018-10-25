import * as _ from 'lodash';

import {expect} from 'chai';
import 'mocha';

import {Constants} from './common/constants';
import * as Bitcore from 'bitcore-lib';
import {
  deriveAddress,
  getCopayerHash,
  verifyMessage,
  decryptMessage,
  xPubToCopayerId,
  verifyRequestPubKey,
  buildTx,
  hashMessage,
  signMessage,
  formatAmount,
  encryptMessage,
  decryptMessageNoThrow,
  getProposalHash,
  privateKeyToAESKey,
  signRequestPubKey,
} from './utils';

let toSatoshi = function(btc) {
  if (_.isArray(btc)) {
    return _.map(btc, toSatoshi);
  } else {
    return parseFloat((btc * 1e8).toPrecision(12));
  }
};

let generateUtxos = function(
  scriptType,
  publicKeyRing,
  path,
  requiredSignatures,
  amounts,
) {
  amounts = [].concat(amounts);
  return _.map(amounts, (amount, i) => {
    const address = deriveAddress(
      scriptType,
      publicKeyRing,
      path,
      requiredSignatures,
      'testnet',
      'btc',
    );

    let scriptPubKey;
    switch (scriptType) {
      case Constants.SCRIPT_TYPES.P2SH:
        scriptPubKey = Bitcore.Script.buildMultisigOut(
          address.publicKeys,
          requiredSignatures,
        ).toScriptHashOut();
        break;
      case Constants.SCRIPT_TYPES.P2PKH:
        scriptPubKey = Bitcore.Script.buildPublicKeyHashOut(address.address);
        break;
    }

    return {
      txid: Bitcore.crypto.Hash.sha256(new Buffer(i)).toString('hex'),
      vout: 100,
      satoshis: toSatoshi(amount),
      scriptPubKey: scriptPubKey.toBuffer().toString('hex'),
      address: address.address,
      path: path,
      publicKeys: address.publicKeys,
    };
  });
};

describe('Utils', () => {
  describe('#hashMessage', () => {
    it('should create a hash', () => {
      let res = hashMessage('hola');
      expect(res.toString('hex')).to.equal(
        '4102b8a140ec642feaa1c645345f714bc7132d4fd2f7f6202db8db305a96172f',
      );
    });
  });

  describe('#copayerHash', () => {
    it('should get copayer hash', () => {
      const name = 'John';
      const reqPubKey = new Bitcore.PrivateKey().toPublicKey();
      const xPrivKey = new Bitcore.HDPrivateKey();
      const xPubKey = new Bitcore.HDPublicKey(xPrivKey);
      let copayerHash = getCopayerHash(name, xPubKey, reqPubKey);
      expect(copayerHash).to.equal(copayerHash);
    });
  });

  describe('#xPubToCopayerId', () => {
    it('should get copayer id', () => {
      const coin = 'btc';
      const xPrivKey = new Bitcore.HDPrivateKey();
      const xPubKey = new Bitcore.HDPublicKey(xPrivKey);
      const copayerId = xPubToCopayerId(coin, xPubKey);
      expect(copayerId).to.equal(copayerId);
    });
  });

  describe('#signMessage', () => {
    it('should sign a message', () => {
      const sig = signMessage(
        'hola',
        '09458c090a69a38368975fb68115df2f4b0ab7d1bc463fc60c67aa1730641d6c',
      );
      expect(sig).to.equal(sig);
      expect(sig).to.equal(
        '3045022100f2e3369dd4813d4d42aa2ed74b5cf8e364a8fa13d43ec541e4bc29525e0564c302205b37a7d1ca73f684f91256806cdad4b320b4ed3000bee2e388bcec106e0280e0',
      );
    });
    it('should fail to sign with wrong args', () => {
      expect(() => {
        signMessage(
          'hola',
          '03bec86ad4a8a91fe7c11ec06af27246ec55094db3d86098b7d8b2f12afe47627f',
        );
      }).to.throw('Number must be less than N');
    });
  });

  describe('#verifyMessage', () => {
    it('should fail to verify a malformed signature', () => {
      const res = verifyMessage(
        'hola',
        'badsignature',
        '02555a2d45e309c00cc8c5090b6ec533c6880ab2d3bc970b3943def989b3373f16',
      );
      expect(res).to.equal(res);
      expect(res).to.equal(false);
    });
    it('should fail to verify a null signature', () => {
      const res = verifyMessage(
        'hola',
        null,
        '02555a2d45e309c00cc8c5090b6ec533c6880ab2d3bc970b3943def989b3373f16',
      );
      expect(res).to.equal(res);
      expect(res).to.equal(false);
    });
    it('should fail to verify with wrong pubkey', () => {
      const res = verifyMessage(
        'hola',
        '3045022100d6186930e4cd9984e3168e15535e2297988555838ad10126d6c20d4ac0e74eb502201095a6319ea0a0de1f1e5fb50f7bf10b8069de10e0083e23dbbf8de9b8e02785',
        '02555a2d45e309c00cc8c5090b6ec533c6880ab2d3bc970b3943def989b3373f16',
      );
      expect(res).to.equal(res);
      expect(res).to.equal(false);
    });
    it('should verify', () => {
      const res = verifyMessage(
        'hola',
        '3045022100d6186930e4cd9984e3168e15535e2297988555838ad10126d6c20d4ac0e74eb502201095a6319ea0a0de1f1e5fb50f7bf10b8069de10e0083e23dbbf8de9b8e02785',
        '03bec86ad4a8a91fe7c11ec06af27246ec55094db3d86098b7d8b2f12afe47627f',
      );
      expect(res).to.equal(res);
      expect(res).to.equal(true);
    });
  });

  describe('#formatAmount', () => {
    it('should successfully format short amount', () => {
      const cases = [
        {
          args: [1, 'bit'],
          expected: '0',
        },
        {
          args: [1, 'btc'],
          expected: '0.00',
        },
        {
          args: [400050000, 'btc'],
          expected: '4.0005',
        },
        {
          args: [400000000, 'btc'],
          expected: '4.00',
        },
        {
          args: [49999, 'btc'],
          expected: '0.000499',
        },
        {
          args: [100000000, 'btc'],
          expected: '1.00',
        },
        {
          args: [0, 'bit'],
          expected: '0',
        },
        {
          args: [12345678, 'bit'],
          expected: '123,456',
        },
        {
          args: [12345678, 'btc'],
          expected: '0.123456',
        },
        {
          args: [12345611, 'btc'],
          expected: '0.123456',
        },
        {
          args: [1234, 'btc'],
          expected: '0.000012',
        },
        {
          args: [1299, 'btc'],
          expected: '0.000012',
        },
        {
          args: [1234567899999, 'btc'],
          expected: '12,345.678999',
        },
        {
          args: [
            12345678,
            'bit',
            {
              thousandsSeparator: '.',
            },
          ],
          expected: '123.456',
        },
        {
          args: [
            12345678,
            'btc',
            {
              decimalSeparator: ',',
            },
          ],
          expected: '0,123456',
        },
        {
          args: [
            1234567899999,
            'btc',
            {
              thousandsSeparator: ' ',
              decimalSeparator: ',',
            },
          ],
          expected: '12 345,678999',
        },
        {
          args: [10000, 'bch'],
          expected: undefined,
        },
      ];

      _.each(cases, testCase => {
        expect(formatAmount.apply(this, testCase.args)).to.equal(
          testCase.expected,
        );
      });
    });
    it('should successfully format full amount', () => {
      const cases = [
        {
          args: [1, 'bit'],
          expected: '0.01',
        },
        {
          args: [1, 'btc'],
          expected: '0.00000001',
        },
        {
          args: [0, 'bit'],
          expected: '0.00',
        },
        {
          args: [12345678, 'bit'],
          expected: '123,456.78',
        },
        {
          args: [12345678, 'btc'],
          expected: '0.12345678',
        },
        {
          args: [1234567, 'btc'],
          expected: '0.01234567',
        },
        {
          args: [12345611, 'btc'],
          expected: '0.12345611',
        },
        {
          args: [1234, 'btc'],
          expected: '0.00001234',
        },
        {
          args: [1299, 'btc'],
          expected: '0.00001299',
        },
        {
          args: [1234567899999, 'btc'],
          expected: '12,345.67899999',
        },
        {
          args: [
            12345678,
            'bit',
            {
              thousandsSeparator: "'",
            },
          ],
          expected: "123'456.78",
        },
        {
          args: [
            12345678,
            'btc',
            {
              decimalSeparator: ',',
            },
          ],
          expected: '0,12345678',
        },
        {
          args: [
            1234567899999,
            'btc',
            {
              thousandsSeparator: ' ',
              decimalSeparator: ',',
            },
          ],
          expected: '12 345,67899999',
        },
      ];

      _.each(cases, (testCase: any) => {
        testCase.args[2] = testCase.args[2] || {};
        testCase.args[2].fullPrecision = true;
        expect(formatAmount.apply(this, testCase.args)).to.equal(
          testCase.expected,
        );
      });
    });
  });

  describe('#signMessage #verifyMessage round trip', () => {
    it('should sign and verify', () => {
      const msg =
        'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.';
      const sig = signMessage(
        msg,
        '09458c090a69a38368975fb68115df2f4b0ab7d1bc463fc60c67aa1730641d6c',
      );
      expect(
        verifyMessage(
          msg,
          sig,
          '03bec86ad4a8a91fe7c11ec06af27246ec55094db3d86098b7d8b2f12afe47627f',
        ),
      ).to.equal(true);
    });
  });

  describe('#encryptMessage #decryptMessage round trip', () => {
    const message = 'Hello world!';
    const pwd = 'ezDRS2NRchMJLf1IWtjL5A==';
    it('should encrypt and decrypt', () => {
      const ct = encryptMessage(message, pwd);
      const msg = decryptMessage(ct, pwd);
      expect(msg).to.equal(message);
    });
  });

  describe('#decryptMessage should throw', () => {
    const message = 'Hello world!';
    const pwd = 'ezDRS2NRchMJLf1IWtjL5A==';
    it('should fail: bad json', () => {
      expect(() => {
        decryptMessage('abc', pwd);
      }).to.throw(/json decode/);
    });
    it('should fail: bad password', () => {
      const ct = encryptMessage(message, pwd);
      expect(() => {
        decryptMessage(ct, 'abc');
      }).to.throw(/invalid aes key size/);
    });
  });

  describe('#decryptMessageNoThrow should not throw', () => {
    it('should encrypt and decrypt', () => {
      const pwd = 'ezDRS2NRchMJLf1IWtjL5A==';
      const ct = encryptMessage('hello world', pwd);
      const msg = decryptMessageNoThrow(ct, pwd);
      expect(msg).to.equal('hello world');
    });
    it('should encrypt and  fail to decrypt', () => {
      const pwd = 'ezDRS2NRchMJLf1IWtjL5A==';
      const ct = encryptMessage('hello world', pwd);
      const msg = decryptMessageNoThrow(ct, 'hola');
      expect(msg).to.equal('<ECANNOTDECRYPT>');
    });
    it('should failover to decrypt a non-encrypted msg', () => {
      const pwd = 'ezDRS2NRchMJLf1IWtjL5A==';
      const msg = decryptMessageNoThrow('hola mundo', 'hola');
      expect(msg).to.equal('hola mundo');
    });
    it('should failover to decrypt a non-encrypted msg (case 2)', () => {
      const pwd = 'ezDRS2NRchMJLf1IWtjL5A==';
      const msg = decryptMessageNoThrow('{"pepe":1}', 'hola');
      expect(msg).to.equal('{"pepe":1}');
    });
    it('should no try to decrypt empty', () => {
      const msg = decryptMessageNoThrow('', 'hola');
      expect(msg).to.equal('');
    });
    it('should no try to decrypt null', () => {
      const msg = decryptMessageNoThrow(null, 'hola');
      expect(msg).to.equal('');
    });
  });

  describe('#getProposalHash', () => {
    it('should compute hash for old style proposals', () => {
      const hash = getProposalHash(
        'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx',
        1234,
        'the message',
      );
      expect(hash).to.equal(
        'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx|1234|the message|',
      );
    });
    it('should compute hash for arbitrary proposal', () => {
      const header1 = {
        type: 'simple',
        version: '1.0',
        toAddress: 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx',
        amount: 1234,
        message: {
          one: 'one',
          two: 'two',
        },
      };

      const header2 = {
        toAddress: 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx',
        type: 'simple',
        version: '1.0',
        message: {
          two: 'two',
          one: 'one',
        },
        amount: 1234,
      };

      const hash1 = getProposalHash(header1);
      const hash2 = getProposalHash(header2);

      expect(hash1).to.be.a('string');
      expect(hash2).to.be.a('string');
      expect(hash1).to.equal(hash2);
    });
  });

  describe('#privateKeyToAESKey', () => {
    it('should be ok', () => {
      const privKey = new Bitcore.PrivateKey(
        '09458c090a69a38368975fb68115df2f4b0ab7d1bc463fc60c67aa1730641d6c',
      ).toString();
      expect(privateKeyToAESKey(privKey)).to.equal('2HvmUYBSD0gXLea6z0n7EQ==');
    });
    it('should fail if pk has invalid values 1/2', () => {
      const a = privateKeyToAESKey(null);
      expect(a).to.be.undefined;
    });
    it('should fail if pk has invalid values 2/2', () => {
      const a = privateKeyToAESKey('x123');
      expect(a).to.be.undefined;
    });
  });

  describe('#verifyRequestPubKey', () => {
    it('should generate and check request pub key', () => {
      const reqPubKey = new Bitcore.PrivateKey().toPublicKey();
      const xPrivKey = new Bitcore.HDPrivateKey();
      const xPubKey = new Bitcore.HDPublicKey(xPrivKey);

      const sig = signRequestPubKey(reqPubKey.toString(), xPrivKey);
      const valid = verifyRequestPubKey(reqPubKey.toString(), sig, xPubKey);
      expect(valid).to.equal(true);
    });

    it('should fail to check a request pub key with wrong key', () => {
      const reqPubKey =
        '02c2c1c6e75cfc50235ff4a2eb848385c2871b8c94e285ee82eaced1dcd5dd568e';
      const xPrivKey = new Bitcore.HDPrivateKey();
      const xPubKey = new Bitcore.HDPublicKey(xPrivKey);
      const sig = signRequestPubKey(reqPubKey, xPrivKey);

      const xPrivKey2 = new Bitcore.HDPrivateKey();
      const xPubKey2 = new Bitcore.HDPublicKey(xPrivKey2);
      const valid = verifyRequestPubKey(reqPubKey, sig, xPubKey2);
      expect(valid).to.equal(false);
    });
  });

  describe('#buildTx', () => {
    const masterPrivateKey =
      'tprv8ZgxMBicQKsPd8U9aBBJ5J2v8XMwKwZvf8qcu2gLK5FRrsrPeSgkEcNHqKx4zwv6cP536m68q2UD7wVM24zdSCpaJRmpowaeJTeVMXL5v5k';
    const derivedPrivateKey = {
      BIP44: new Bitcore.HDPrivateKey(masterPrivateKey)
        .deriveChild("m/44'/1'/0'")
        .toString(),
      BIP45: new Bitcore.HDPrivateKey(masterPrivateKey)
        .deriveChild("m/45'")
        .toString(),
      BIP48: new Bitcore.HDPrivateKey(masterPrivateKey)
        .deriveChild("m/48'/1'/0'")
        .toString(),
    };
    const toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
    const changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

    it('should build a BTC transaction correctly (BIP44)', function() {
      const publicKeyRing = [
        {
          xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey['BIP44']),
        },
      ];

      const utxos = generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [
        1000,
        2000,
      ]);
      const txp = {
        version: '2.0.0',
        inputs: utxos,
        toAddress: toAddress,
        amount: 1200,
        changeAddress: {
          address: changeAddress,
        },
        requiredSignatures: 1,
        outputOrder: [0, 1],
        fee: 10050,
        derivationStrategy: 'BIP44',
        addressType: 'P2PKH',
      };
      const t = buildTx(txp);
      const bitcoreError = t.getSerializationError({
        disableIsFullySigned: true,
        disableSmallFees: true,
        disableLargeFees: true,
      });

      expect(bitcoreError).to.be.undefined;
      expect(t.getFee()).to.equal(10050);
    });
    it('should build a tx correctly (BIP48)', function() {
      const publicKeyRing = [
        {
          xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey['BIP48']),
        },
      ];

      const utxos = generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [
        1000,
        2000,
      ]);
      const txp = {
        version: '2.0.0',
        inputs: utxos,
        toAddress: toAddress,
        amount: 1200,
        changeAddress: {
          address: changeAddress,
        },
        requiredSignatures: 1,
        outputOrder: [0, 1],
        fee: 10050,
        derivationStrategy: 'BIP48',
        addressType: 'P2PKH',
      };
      const t = buildTx(txp);
      const bitcoreError = t.getSerializationError({
        disableIsFullySigned: true,
        disableSmallFees: true,
        disableLargeFees: true,
      });

      expect(bitcoreError).to.be.undefined;
      expect(t.getFee()).to.equal(10050);
    });
  });
});
