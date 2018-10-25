import * as _ from 'lodash';

import {expect} from 'chai';
import 'mocha';

import {deriveAddress, getCopayerHash, signMessage} from './utils';
import {Verifier} from './verifier';
import {Constants} from './common/constants';
import * as Bitcore from 'bitcore-lib';

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
      satoshis: amount,
      scriptPubKey: scriptPubKey.toBuffer().toString('hex'),
      address: address.address,
      path: path,
      publicKeys: address.publicKeys,
    };
  });
};

const REQUEST_PUBLIC_KEY =
  '025a28b88244521b0150c03b84bc02c6aa5f21ecc3ac8b887b12b8432715554fc5';
const COPAYER_ID =
  'd27c195bef2d2e55ab4f3373bae590ef54c41ec5f7cd36a4da762e6127f01143';
const COPAYER_NAME = 'me';
const NETWORK = 'testnet';
const COIN = 'btc';
const SCRIPT_TYPE = 'P2PKH';
const PATH = 'm/1/0';
const X_PRIVATE_KEY =
  'tprv8ZgxMBicQKsPe1zbzcMoTQFsRB5y6RShBadvM1QqitGBRP9UvWDmj9RseqaBU9NmVrZ9JMEMWBRGoR1TbaqEVV7mwhGcvDv1SNLVZjMPyVT';
const X_PUBLIC_KEY =
  'tpubDD5rXm6mmbQuTAh82P9XiTUWxrDctg3mgEjK3t1rHtDLcUHHHgv5MH1C1PYbCAbJZo9W4WLhchJ6qBr8VjBEFMEY3p7CneokQQaBzWiYLac';
const WALLET_PRIVATE_KEY =
  'd676689819383861fc54f87e6e419e8b0984a95f6120aef950bc59473978b3cc';

const DERIVED_PRIVATE_KEY = {
  BIP44: new Bitcore.HDPrivateKey(X_PRIVATE_KEY)
    .deriveChild("m/44'/1'/0'")
    .toString(),
  BIP45: new Bitcore.HDPrivateKey(X_PRIVATE_KEY)
    .deriveChild("m/45'")
    .toString(),
  BIP48: new Bitcore.HDPrivateKey(X_PRIVATE_KEY)
    .deriveChild("m/48'/1'/0'")
    .toString(),
};
const PUBLIC_KEY_RING = [
  {
    copayerName: COPAYER_NAME,
    requestPubKey: REQUEST_PUBLIC_KEY,
    xPubKey: new Bitcore.HDPublicKey(DERIVED_PRIVATE_KEY['BIP44']).toString(),
  },
];

const CREDENTIALS = {
  copayerId: COPAYER_ID,
  copayerName: COPAYER_NAME,
  xPubKey: X_PUBLIC_KEY,
  walletPrivKey: WALLET_PRIVATE_KEY,
  addressType: SCRIPT_TYPE,
  publicKeyRing: PUBLIC_KEY_RING,
  m: 1,
  n: 1,
  network: NETWORK,
  coin: COIN,
  isComplete: () => {
    return true;
  },
};

const hashCopayer = getCopayerHash(
  COPAYER_NAME,
  X_PUBLIC_KEY,
  REQUEST_PUBLIC_KEY,
);
const COPAYERS = [
  {
    xPrivKey: X_PRIVATE_KEY,
    xPubKey: X_PUBLIC_KEY,
    requestPubKey: REQUEST_PUBLIC_KEY,
    name: COPAYER_NAME,
    signature: signMessage(hashCopayer, WALLET_PRIVATE_KEY),
  },
];

const PERSONAL_ENCRYPTING_KEY = 'zMzG7goUTtrLYzc1/m8F1Q==';
const ADDRESS = 'n2hQLTUPgthSUUFL9XdkSADMzJkHHvRjXc';
const CHANGE_ADDRESS = 'n3m5qKGPCnVwcNQfj4Sk5HkPJDhLHNPF4r';
const UTXOS = generateUtxos(SCRIPT_TYPE, PUBLIC_KEY_RING, PATH, 1, [1000, 200]);
const TXP = {
  creatorId: COPAYER_ID,
  version: '3.0.0',
  inputs: UTXOS,
  toAddress: ADDRESS,
  amount: 1200,
  message: 'first output',
  outputs: [
    {
      toAddress: ADDRESS,
      amount: 500,
      message: 'first output',
    },
    {
      toAddress: ADDRESS,
      amount: 700,
      message: 'second output',
    },
  ],
  changeAddress: {
    address: CHANGE_ADDRESS,
  },
  requiredSignatures: 1,
  outputOrder: [0, 1],
  fee: 10050,
  derivationStrategy: 'BIP44',
  addressType: SCRIPT_TYPE,
};

const ARGS = {
  toAddress: ADDRESS,
  amount: 1200,
  message:
    '{"iv":"khelHrHXZwIFOI6cbYoITA==","v":1,"iter":1,"ks":128,"ts":64,"mode":"ccm","adata":"","cipher":"aes","ct":"mxrRrmZ8Vgu2ow32Tjnkyc890aY="}',
  outputs: [
    {
      toAddress: ADDRESS,
      amount: 500,
      message:
        '{"iv":"khelHrHXZwIFOI6cbYoITA==","v":1,"iter":1,"ks":128,"ts":64,"mode":"ccm","adata":"","cipher":"aes","ct":"mxrRrmZ8Vgu2ow32Tjnkyc890aY="}',
    },
    {
      toAddress: ADDRESS,
      amount: 700,
      message:
        '{"iv":"P5DladG6Xx5tyAVaRkZgBQ==","v":1,"iter":1,"ks":128,"ts":64,"mode":"ccm","adata":"","cipher":"aes","ct":"GG6TagsYw8EYpEUxaoxMvU2HFuvN"}',
    },
  ],
  changeAddress: CHANGE_ADDRESS,
  fee: 10050,
  addressType: SCRIPT_TYPE,
};

const TXP_CREDENTIAL_FAKE = {
  version: '1.0.0',
  derivationStrategy: 'BIP44',
  account: 0,
  coin: 'btc',
  network: 'testnet',
  xPrivKey:
    'tprv8ZgxMBicQKsPdzZxSwFQzHf3xf9a2bHsrre4o9eXN3pQD6pw8H2rptWLNVvUzF1cubeUQLM3jKx7e3JNhogddgRwFiPGTBfZYsV66hS3Vxe',
  xPubKey:
    'tpubDDtdCg3fp26VSB9nbyeB21cFRo1oyFPjGL3oXAHWmqnJ3jteUwsyShkeX9EQLTSfEVpBsg5pnwMKqMgg8ZXv73pqKdQGUbeppiuMFvTF6fG',
  requestPrivKey:
    '8886eb440eeff5f0203058f2876b02fed327e4e8a337701d95e6e96c394a498a',
  requestPubKey:
    '02331c96e46d395172a98bd9e503e0c972cf2c8567b50cfef3742f859f51216398',
  copayerId: '13f14b2914e676a14e7308bffdaa479f779814d8d2af08ceadd85b13eaf48514',
  publicKeyRing: [
    {
      xPubKey:
        'tpubDDqmZzkf2dNVYHkb3nkrSqsuWnDyhd7q2yg3jBF8jFzikiBQxd5Zvmmv1pY42wL4PCcoBFMzMmTxZ6bQDjCj1iP8apdN4ucWZFdjkeQ9ceK',
      requestPubKey:
        '0381fed5f86a5d45f263c6f50b49837b6e3a64b85577cc2c16447c3cccb42cf080',
      copayerName: 'desktop',
    },
    {
      xPubKey:
        'tpubDDtdCg3fp26VSB9nbyeB21cFRo1oyFPjGL3oXAHWmqnJ3jteUwsyShkeX9EQLTSfEVpBsg5pnwMKqMgg8ZXv73pqKdQGUbeppiuMFvTF6fG',
      requestPubKey:
        '02331c96e46d395172a98bd9e503e0c972cf2c8567b50cfef3742f859f51216398',
      copayerName: 'browser',
    },
  ],
  walletId: 'f39c02bd-e1b4-419e-9b17-e0cdaea6a7d3',
  walletName: 'Test-desktop',
  m: 2,
  n: 2,
  walletPrivKey:
    '6ee1b720ceb5933b51796e1f89423b90d393d251bba3fd58839a53fc9d0a4553',
  personalEncryptingKey: 'KuQhFD0VDWN93EphomJZRA==',
  sharedEncryptingKey: 'T59OXYq7E1c9qVN9+gKhVQ==',
  copayerName: 'browser',
  mnemonic:
    'tool small river increase tackle fence salt toast brief sock device trigger',
  entropySource:
    '83af3a0e9c6645d991fd55ab5695406b19cb71c68decff1a47b8be375ce8c10c',
  mnemonicHasPassphrase: false,
  compliantDerivation: true,
  addressType: 'P2SH',
};
const TXP_FAKE = {
  version: 3,
  createdOn: 1537475723,
  id: '0fc98a83-445a-4fd7-9daa-c9edf21db83a',
  walletId: 'f39c02bd-e1b4-419e-9b17-e0cdaea6a7d3',
  creatorId: '13f14b2914e676a14e7308bffdaa479f779814d8d2af08ceadd85b13eaf48514',
  coin: 'btc',
  network: 'testnet',
  message: null,
  payProUrl: null,
  changeAddress: {
    version: '1.0.0',
    createdOn: 1537475723,
    address: '2Muxj5pZoaR7WKduVsPAC4yya8sMPZMbLRm',
    walletId: 'f39c02bd-e1b4-419e-9b17-e0cdaea6a7d3',
    isChange: true,
    path: 'm/1/113',
    publicKeys: [
      '036c20d09c44a8c965abd723f2892b96ab959dad7be455e283955eca561dcfaf02',
      '035b87b4e61d3d16cc41554af31013294ea87c35227e2aec62802efd679d3def64',
    ],
    coin: 'btc',
    network: 'testnet',
    type: 'P2SH',
  },
  outputs: [
    {
      amount: 100000,
      toAddress: 'n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi',
      message: null,
      encryptedMessage: null,
    },
  ],
  outputOrder: [0, 1],
  walletM: 2,
  walletN: 2,
  requiredSignatures: 2,
  requiredRejections: 1,
  status: 'temporary',
  actions: [],
  feeLevel: 'normal',
  feePerKb: 7216,
  excludeUnconfirmedUtxos: true,
  addressType: 'P2SH',
  amount: 100000,
  inputs: [
    {
      txid: '965cddc7c5507de5df09e79dd043182f3ba000ea81ccf0b8bc9d9604d72916c3',
      vout: 1,
      address: '2MxwmRKHnmjBMdEkyMSn9krZGZWk1CyzmCz',
      scriptPubKey: 'a9143e8381522d6da5b61c3a829e43eaa68bad78f92d87',
      satoshis: 200000,
      confirmations: 102127,
      locked: false,
      path: 'm/0/64',
      publicKeys: [
        '03654c88e2980f2875c95e7892ee6bb683719c8eb3061dfee3f1ecb06e6710f3e3',
        '03a6b149d50d75823650ca8461319890f001ab7e3f6250fda5641070471aee5f1f',
      ],
    },
  ],
  inputPaths: ['m/0/64'],
  fee: 2569,
  encryptedMessage: null,
  creatorName: '',
  hasUnconfirmedInputs: false,
  feeRatePerStr: '2.50%',
  feeTooHigh: false,
};
const TXP_SIGNATURE_FAKE =
  '30440220511e83f0fe1d36ba2a597375a331efc4f58ec74f30e8316f5491ab2021891bd102204bce66ba4e31d2f4a97dc52419f0dbc86153a09a1dba6cc092fe07a5580fdf27';

describe('Verifier', () => {
  const verifier = new Verifier();

  let credentials = CREDENTIALS;
  let copayers = COPAYERS;
  let txp = TXP;
  let args = ARGS;
  let fake_credentials = TXP_CREDENTIAL_FAKE;
  let fake_txp = TXP_FAKE;

  beforeEach(() => {
    credentials.network = 'testnet';
    credentials.isComplete = () => {
      return true;
    };
    fake_txp['changeAddress'].address = '2Muxj5pZoaR7WKduVsPAC4yya8sMPZMbLRm';
    fake_txp['version'] = 3;
    fake_txp['proposalSignature'] = TXP_SIGNATURE_FAKE;
    fake_credentials['isComplete'] = () => {
      return true;
    };
  });

  describe('#checkAddress', () => {
    const address = deriveAddress(
      SCRIPT_TYPE,
      PUBLIC_KEY_RING,
      PATH,
      credentials.m,
      credentials.network,
      credentials.coin,
    );
    it('should check a bitcoin address', () => {
      expect(verifier.checkAddress(credentials, address)).to.be.true;
    });
    it('should return false if checking as livenet a testnet address', () => {
      credentials.network = 'livenet';
      expect(verifier.checkAddress(credentials, address)).to.be.false;
    });
    it('should throw error if wallet not completed', () => {
      credentials.isComplete = () => {
        return false;
      };
      expect(() => {
        verifier.checkAddress(credentials, address);
      }).to.throw();
    });
  });

  describe('#checkCopayers', () => {
    it('should check copayers', () => {
      expect(verifier.checkCopayers(credentials, copayers)).to.be.true;
    });
    it('should fail copayers 1/3', () => {
      credentials.xPubKey = '';
      expect(verifier.checkCopayers(credentials, copayers)).to.be.false;
    });
    it('should fail copayers 2/3', () => {
      copayers[0].signature = 'xx';
      expect(verifier.checkCopayers(credentials, copayers)).to.be.false;
    });
    it('should fail copayers 3/3', () => {
      copayers[0].name = '';
      expect(verifier.checkCopayers(credentials, copayers)).to.be.false;
    });
    it('should throw copayers', () => {
      credentials.walletPrivKey = '';
      expect(() => {
        verifier.checkCopayers(credentials, copayers);
      }).to.throw();
    });
  });

  describe('#checkProposalCreation', () => {
    it('should check transaction proposal', () => {
      expect(verifier.checkProposalCreation(args, txp, PERSONAL_ENCRYPTING_KEY))
        .to.be.true;
    });
    it('should fail transaction proposal due bad encrypting key', () => {
      expect(verifier.checkProposalCreation(args, txp, 'bad encrypting key')).to
        .be.false;
    });
    it('should fail transaction proposal due message', () => {
      args.outputs[0].message = 'no json format';
      expect(verifier.checkProposalCreation(args, txp, PERSONAL_ENCRYPTING_KEY))
        .to.be.false;
    });
  });

  describe('#checkTxProposalSignature', () => {
    it('should check transaction proposal signature', () => {
      expect(verifier.checkTxProposalSignature(fake_credentials, fake_txp)).to
        .be.true;
    });
    it('should fail due to wrong address', () => {
      fake_txp['changeAddress'].address = 'n3m5qKGPCnVwcNQfj4Sk5HkPJDhLHNPF4r';
      expect(verifier.checkTxProposalSignature(fake_credentials, fake_txp)).to
        .be.false;
    });
    it('should fail due to bad signature', () => {
      fake_txp['proposalSignature'] = 'bad signature';
      expect(verifier.checkTxProposalSignature(fake_credentials, fake_txp)).to
        .be.false;
    });
    it('should fail due to incorrect version', () => {
      fake_txp['version'] = 2;
      expect(() => {
        verifier.checkTxProposalSignature(fake_credentials, fake_txp);
      }).to.throw('not supported');
    });
    it('should fail due to incomplete wallet', () => {
      fake_credentials['isComplete'] = () => {
        return false;
      };
      expect(() => {
        verifier.checkTxProposalSignature(fake_credentials, fake_txp);
      }).to.throw('not completed');
    });
  });

  describe('#checkPaypro', () => {
    const payproOpts = {
      toAddress: ADDRESS,
      amount: 1200,
    };
    it('should check payment protocol', () => {
      expect(verifier.checkPaypro(txp, payproOpts)).to.be.true;
    });
    it('should check payment protocol for old txp version', () => {
      txp.version = '2.0.0';
      expect(verifier.checkPaypro(txp, payproOpts)).to.be.true;
    });
    it('should fail due to wrong amount', () => {
      txp.amount = 50000;
      expect(verifier.checkPaypro(txp, payproOpts)).to.be.false;
    });
  });

  describe('#checkTxProposal', () => {
    let opts = null;
    it('should check transaction proposal signature', () => {
      expect(verifier.checkTxProposal(fake_credentials, fake_txp, opts)).to.be
        .true;
    });
    it('should check transaction proposal payment protocol', () => {
      opts = {
        paypro: {
          toAddress: 'n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi',
          amount: 100000,
        },
      };
      expect(verifier.checkTxProposal(fake_credentials, fake_txp, opts)).to.be
        .true;
    });
  });
});
