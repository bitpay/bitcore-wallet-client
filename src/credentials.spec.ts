import * as _ from 'lodash';

import { expect } from 'chai';
import 'mocha';

import { Constants } from './common/constants';
import { Credentials } from './credentials';

const TestData = require('../test/testdata');

describe('Credentials', () => {


  describe('#create', () => {
    it('should create', () => {
      const c = new Credentials().create('btc', 'livenet');
      expect(c.xPrivKey).to.equal(c.xPrivKey);
      expect(c.copayerId).to.equal(c.copayerId);
    });

    it('should create random credentials', () => {
      let c;
      let all = {};
      for (let i = 0; i < 10; i++) {
        c = new Credentials().create('btc', 'livenet');
        const exist = all[c.xPrivKey];
        expect(exist).to.be.undefined;
        all[c.xPrivKey] = 1;
      }
    });
  });

  describe('#getBaseAddressDerivationPath', () => {
    it('should return path for livenet', () => {
      const credential = new Credentials()
      const c = credential.create('btc', 'livenet');
      const path = credential.getBaseAddressDerivationPath();
      expect(path).to.equal("m/44'/0'/0'");
    });
    it('should return path for testnet account 2', () => {
      const credential = new Credentials()
      const c = credential.create('btc', 'testnet');
      c.account = 2;
      const path = credential.getBaseAddressDerivationPath();
      expect(path).to.equal("m/44'/1'/2'");
    });
    it('should return path for BIP45', () => {
      const credential = new Credentials()
      const c = credential.create('btc', 'livenet');
      c.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP45;
      var path = credential.getBaseAddressDerivationPath();
      expect(path).to.equal("m/45'");
    });
  });

  describe('#getDerivedXPrivKey', () => {
    it('should derive extended private key from master livenet', () => {
      const credential = new Credentials()
      const c = credential.fromExtendedPrivateKey('btc', 'xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', 0, 'BIP44');
      const xpk = credential.getDerivedXPrivKey().toString();
      expect(xpk).to.equal('xprv9xud2WztGSSBPDPDL9RQ3rG3vucRA4BmEnfAdP76bTqtkGCK8VzWjevLw9LsdqwH1PEWiwcjymf1T2FLp12XjwjuCRvcSBJvxDgv1BDTbWY');
    });
    it('should derive extended private key from master testnet', () => {
      const credential = new Credentials()
      const c = credential.fromExtendedPrivateKey('btc', 'tprv8ZgxMBicQKsPfPX8avSJXY1tZYJJESNg8vR88i8rJFkQJm6HgPPtDEmD36NLVSJWV5ieejVCK62NdggXmfMEHog598PxvXuLEsWgE6tKdwz', 0, 'BIP44');
      const xpk = credential.getDerivedXPrivKey().toString();
      expect(xpk).to.equal('tprv8gBu8N7JbHZs7MsW4kgE8LAYMhGJES9JP6DHsj2gw9Tc5PrF5Grr9ynAZkH1LyWsxjaAyCuEMFKTKhzdSaykpqzUnmEhpLsxfujWHA66N93');
    });
    it('should derive extended private key from master BIP48 livenet', () => {
      const credential = new Credentials()
      const c = credential.fromExtendedPrivateKey('btc', 'xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', 0, 'BIP48');
      const xpk = credential.getDerivedXPrivKey().toString();
      expect(xpk).to.equal('xprv9yaGCLKPS2ovEGw987MZr4DCkfZHGh518ndVk3Jb6eiUdPwCQu7nYru59WoNkTEQvmhnv5sPbYxeuee5k8QASWRnGV2iFX4RmKXEQse8KnQ');
    });
    it('should derive extended private key from master livenet (BIP45)', () => {
      const credential = new Credentials()
      const c = credential.fromExtendedPrivateKey('btc', 'xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', 0, 'BIP45');
      const xpk = credential.getDerivedXPrivKey().toString();
      expect(xpk).to.equal('xprv9vDaAbbvT8LHKr8v5A2JeFJrnbQk6ZrMDGWuiv2vZgSyugeV4RE7Z9QjBNYsdafdhwEGb6Y48DRrXFVKvYRAub9ExzcmJHt6Js6ybJCSssm');
    });
    it('should set addressType & BIP45', () => {
      const credential = new Credentials()
      const c = credential.fromExtendedPrivateKey('btc', 'xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', 8, 'BIP45');
      credential.addWalletInfo(1, 'name', 1, 1, 'juan');
      expect(c.account).to.equal(8);
    });
    it('should derive compliant child', () => {
      const credential = new Credentials()
      const c = credential.fromExtendedPrivateKey('btc', 'tprv8ZgxMBicQKsPd8U9aBBJ5J2v8XMwKwZvf8qcu2gLK5FRrsrPeSgkEcNHqKx4zwv6cP536m68q2UD7wVM24zdSCpaJRmpowaeJTeVMXL5v5k', 0, 'BIP44');
      expect(c.compliantDerivation).to.be.true;
      const xpk = credential.getDerivedXPrivKey().toString();
      expect(xpk).to.equal('tprv8gXvQvjGt7oYCTRD3d4oeQr9B7JLuC2B6S854F4XWCQ4pr9NcjokH9kouWMAp1MJKy4Y8QLBgbmPtk3i7RegVzaWhWsnVPi4ZmykJXt4HeV');
    });
    it('should derive non-compliant child', () => {
      const credential = new Credentials()
      const c = credential.fromExtendedPrivateKey('btc', 'tprv8ZgxMBicQKsPd8U9aBBJ5J2v8XMwKwZvf8qcu2gLK5FRrsrPeSgkEcNHqKx4zwv6cP536m68q2UD7wVM24zdSCpaJRmpowaeJTeVMXL5v5k', 0, 'BIP44', {
        nonCompliantDerivation: true
      });
      expect(c.compliantDerivation).to.be.false;
      const xpk = credential.getDerivedXPrivKey().toString();
      expect(xpk).to.equal('tprv8gSy16H5hQ1MKNHzZDzsktr4aaGQSHg4XYVEbfsEiGSBcgw4J8dEm8uf19FH4L9h6W47VBKtc3bbYyjb6HAm6QdyRLpB6fsA7bW19RZnby2');
    });
  });

  describe('#fromExtendedPrivateKey', () => {
    it('should create credentials from seed', () => {
      const credential = new Credentials()
      const xPriv = 'xprv9s21ZrQH143K2TjT3rF4m5AJcMvCetfQbVjFEx1Rped8qzcMJwbqxv21k3ftL69z7n3gqvvHthkdzbW14gxEFDYQdrRQMub3XdkJyt3GGGc';
      const c = credential.fromExtendedPrivateKey('btc', xPriv, 0, 'BIP44');

      expect(c.xPrivKey).to.equal('xprv9s21ZrQH143K2TjT3rF4m5AJcMvCetfQbVjFEx1Rped8qzcMJwbqxv21k3ftL69z7n3gqvvHthkdzbW14gxEFDYQdrRQMub3XdkJyt3GGGc');
      expect(c.xPubKey).to.equal('xpub6DUean44k773kxbUq8QpSmAPFaNCpk5AzrxbFRAMsNCZBGD15XQVnRJCgNd8GtJVmDyDZh89NPZz1XPQeX5w6bAdLGfSTUuPDEQwBgKxfh1');
      expect(c.copayerId).to.equal('bad66ef88ad8dec08e36d576c29b4f091d30197f04e166871e64bf969d08a958');
      expect(c.network).to.equal('livenet');
      expect(c.personalEncryptingKey).to.equal('M4MTmfRZaTtX6izAAxTpJg==');
      expect(c.walletPrivKey).to.be.undefined;
    });

    it('should create credentials from seed and walletPrivateKey', () => {
      const credential = new Credentials()
      const xPriv = 'xprv9s21ZrQH143K2TjT3rF4m5AJcMvCetfQbVjFEx1Rped8qzcMJwbqxv21k3ftL69z7n3gqvvHthkdzbW14gxEFDYQdrRQMub3XdkJyt3GGGc';

      const wKey = 'a28840e18650b1de8cb83bcd2213672a728be38a63e70680b0c2be9c452e2d4d';
      const c = credential.fromExtendedPrivateKey('btc', xPriv, 0, 'BIP44', { walletPrivKey: 'a28840e18650b1de8cb83bcd2213672a728be38a63e70680b0c2be9c452e2d4d'});

      expect(c.xPrivKey).to.equal('xprv9s21ZrQH143K2TjT3rF4m5AJcMvCetfQbVjFEx1Rped8qzcMJwbqxv21k3ftL69z7n3gqvvHthkdzbW14gxEFDYQdrRQMub3XdkJyt3GGGc');
      expect(c.walletPrivKey).to.equal(wKey);
    });

    describe('Compliant derivation', () => {
      it('should create compliant base address derivation key', () => {
      const credential = new Credentials()
        const xPriv = 'xprv9s21ZrQH143K4HHBKb6APEoa5i58fxeFWP1x5AGMfr6zXB3A6Hjt7f9LrPXp9P7CiTCA3Hk66cS4g8enUHWpYHpNhtufxSrSpcbaQyVX163';
        const c = credential.fromExtendedPrivateKey('btc', xPriv, 0, 'BIP44');
        expect(c.xPubKey).to.equal('xpub6CUtFEwZKBEyX6xF4ECdJdfRBBo69ufVgmRpy7oqzWJBSadSZ3vaqvCPNFsarga4UWcgTuoDQL7ZnpgWkUVUAX3oc7ej8qfLEuhMALGvFwX');
      });

      it('should create compliant request key', () => {
        const credential = new Credentials()
        const xPriv = 'xprv9s21ZrQH143K3xMCR1BNaUrTuh1XJnsj8KjEL5VpQty3NY8ufgbR8SjZS8B4offHq6Jj5WhgFpM2dcYxeqLLCuj1wgMnSfmZuPUtGk8rWT7';
        const c = credential.fromExtendedPrivateKey('btc', xPriv, 0, 'BIP44');
        expect(c.requestPrivKey).to.equal('559371263eb0b2fd9cd2aa773ca5fea69ed1f9d9bdb8a094db321f02e9d53cec');
      });

      it('should accept non-compliant derivation as a parameter when importing', () => {
        const credential = new Credentials()
        const c = credential.fromExtendedPrivateKey('btc', 'tprv8ZgxMBicQKsPd8U9aBBJ5J2v8XMwKwZvf8qcu2gLK5FRrsrPeSgkEcNHqKx4zwv6cP536m68q2UD7wVM24zdSCpaJRmpowaeJTeVMXL5v5k', 0, 'BIP44', {
          nonCompliantDerivation: true
        });
        expect(c.xPrivKey).to.equal('tprv8ZgxMBicQKsPd8U9aBBJ5J2v8XMwKwZvf8qcu2gLK5FRrsrPeSgkEcNHqKx4zwv6cP536m68q2UD7wVM24zdSCpaJRmpowaeJTeVMXL5v5k');
        expect(c.compliantDerivation).to.be.false;
        expect(c.xPubKey).to.equal('tpubDD919WKKqmh2CqKnSsfUAJWB9bnLbcry6r61tBuY8YEaTBBpvXSpwdXXBGAB1n4JRFDC7ebo7if3psUAMpvQJUBe3LcjuMNA6Y4nP8U9SNg');
        expect(credential.getDerivedXPrivKey().toString()).to.equal("tprv8gSy16H5hQ1MKNHzZDzsktr4aaGQSHg4XYVEbfsEiGSBcgw4J8dEm8uf19FH4L9h6W47VBKtc3bbYyjb6HAm6QdyRLpB6fsA7bW19RZnby2");
      });
    });
  });

  describe('#fromMnemonic', () => {
    it('should create credentials from mnemonic BIP44', () => {
      const credential = new Credentials()
      const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      const c = credential.fromMnemonic('btc', 'livenet', words, '', 0, 'BIP44');
      expect(c.xPrivKey).to.equal('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
      expect(c.network).to.equal('livenet');
      expect(c.account).to.equal(0);
      expect(c.derivationStrategy).to.equal('BIP44');
      expect(c.xPubKey).to.equal('xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj');
      expect(credential.getBaseAddressDerivationPath()).to.equal("m/44'/0'/0'");
    });

    it('should create credentials from mnemonic BIP48', () => {
      const credential = new Credentials()
      const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      const c = credential.fromMnemonic('btc', 'livenet', words, '', 0, 'BIP48');
      expect(c.xPrivKey).to.equal('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
      expect(c.network).to.equal('livenet');
      expect(c.account).to.equal(0);
      expect(c.derivationStrategy).to.equal('BIP48');
      expect(c.xPubKey).to.equal('xpub6CKZtUaK1YHpQbg6CLaGRmsMKLQB1iKzsvmxtyHD6X7gzLqCB2VNZYd1XCxrccQnE8hhDxtYbR1Sakkvisy2J4CcTxWeeGjmkasCoNS9vZm');
      expect(credential.getBaseAddressDerivationPath()).to.equal("m/48'/0'/0'");
    });

    it('should create credentials from mnemonic account 1', () => {
      const credential = new Credentials()
      const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      const c = credential.fromMnemonic('btc', 'livenet', words, '', 1, 'BIP44');
      expect(c.xPrivKey).to.equal('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
      expect(c.account).to.equal(1);
      expect(c.xPubKey).to.equal('xpub6BosfCnifzxcJJ1wYuntGJfF2zPJkDeG9ELNHcKNjezuea4tumswN9sH1psMdSVqCMoJC21Bv8usSeqSP4Sp1tLzW7aY59fGn9GCYzx5UTo');
      expect(credential.getBaseAddressDerivationPath()).to.equal("m/44'/0'/1'");
    });

    it('should create credentials from mnemonic with undefined/null passphrase', () => {
      const credential = new Credentials()
      const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      let c = credential.fromMnemonic('btc', 'livenet', words, undefined, 0, 'BIP44');
      expect(c.xPrivKey).to.equal('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
      c = credential.fromMnemonic('btc', 'livenet', words, null, 0, 'BIP44');
      expect(c.xPrivKey).to.equal('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
    });

    it('should create credentials from mnemonic and passphrase', () => {
      const credential = new Credentials()
      const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      const c = credential.fromMnemonic('btc', 'livenet', words, 'húngaro', 0, 'BIP44');
      expect(c.xPrivKey).to.equal('xprv9s21ZrQH143K2LkGEPHqW8w5vMJ3giizin94rFpSM5Ys5KhDaP7Hde3rEuzC7VpZDtNX643bJdvhHnkbhKMNmLx3Yi6H8WEsHBBox3qbpqq');
    });

    it('should create credentials from mnemonic and passphrase for testnet account 2', () => {
      const credential = new Credentials()
      const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      const c = credential.fromMnemonic('btc', 'testnet', words, 'húngaro', 2, 'BIP44');
      expect(c.xPrivKey).to.equal('tprv8ZgxMBicQKsPd9yntx9LfnZ5EUiFvEm14L4BigEtq43LrvSJZkT39PRJA69r7sCsbKuJ69fMTzWVkeJLpXhKaQDe5MJanrxvCGwEPnNxN85');
      expect(c.network).to.equal('testnet');
      expect(c.xPubKey).to.equal('tpubDCoAP4Ut9MXK5CakPFPudKAP4yCw6Xr7uzV2129v2LTa3eBoPoUGMqi2y3kmh83oRGX93m7EehB6LWan5GTSVD8yUnV5Jc7Kjzfa3Zsf8nE');
      expect(credential.getBaseAddressDerivationPath()).to.equal("m/44'/1'/2'");
    });

    it('should create credentials from mnemonic (ES)', () => {
      const credential = new Credentials()
      const words = 'afirmar diseño hielo fideo etapa ogro cambio fideo toalla pomelo número buscar';
      const c = credential.fromMnemonic('btc', 'livenet', words, '', 0, 'BIP44');
      expect(c.xPrivKey).to.equal('xprv9s21ZrQH143K3H3WtXCn9nHtpi7Fz1ZE9VJErWErhrGL4hV1cApFVo3t4aANoPF7ufcLLWqN168izu3xGQdLaGxXG2qYZF8wWQGNWnuSSon');
      expect(c.network).to.equal('livenet');
    });

    describe('Compliant derivation', () => {
      it('should create compliant base address derivation key from mnemonic', () => {
        const credential = new Credentials()
        const words = "shoulder sphere pull seven top much black copy labor dress depth unit";
        const c = credential.fromMnemonic('btc', 'livenet', words, '', 0, 'BIP44');
        expect(c.xPrivKey).to.equal('xprv9s21ZrQH143K3WoNK8dVjQJpcXhqfwyuBTpuZdc1ZVa9yWW2i7TmM4TLyfPrSKXctQuLgbg3U1WJmodK9yWM26JWeuh2vhT6bmsPPie688n');
        expect(c.xPubKey).to.equal('xpub6DVMaW3r1CcZcsUazSHspjRfZZJzZG3N7GRL4DciY54Z8M4KmRSDrq2hd75VzxKZDXPu4EKiAwCGwiXMxec2pq6oVgtZYxQHSrgtxksWehx');
      });

      it('should create compliant request key from mnemonic', () => {
        const credential = new Credentials()
        const words = "pool stomach bridge series powder mammal betray slogan pass roast neglect reunion";
        const c = credential.fromMnemonic('btc', 'livenet', words, '', 0, 'BIP44');
        expect(c.xPrivKey).to.equal('xprv9s21ZrQH143K3ZMudFRXpEwftifDuJkjLKnCtk26pXhxQuK8bCnytJuUTGkfvaibnCxPQQ9xToUtDAZkJqjm3W62GBXXr7JwhiAz1XWgTUJ');
        expect(c.requestPrivKey).to.equal('7582efa9b71aefa831823592d753704cba9648b810b14b77ee078dfe8b730157');
      });
      it('should accept non-compliant derivation as a parameter when importing', () => {
        const credential = new Credentials()
        const c = credential.fromMnemonic('btc', 'testnet', 'level unusual burger hole call main basic flee drama diary argue legal', '', 0, 'BIP44', {
          nonCompliantDerivation: true
        });
        expect(c.xPrivKey).to.equal('tprv8ZgxMBicQKsPd8U9aBBJ5J2v8XMwKwZvf8qcu2gLK5FRrsrPeSgkEcNHqKx4zwv6cP536m68q2UD7wVM24zdSCpaJRmpowaeJTeVMXL5v5k');
        expect(c.compliantDerivation).to.be.false;
        expect(c.xPubKey).to.equal('tpubDD919WKKqmh2CqKnSsfUAJWB9bnLbcry6r61tBuY8YEaTBBpvXSpwdXXBGAB1n4JRFDC7ebo7if3psUAMpvQJUBe3LcjuMNA6Y4nP8U9SNg');
        expect(credential.getDerivedXPrivKey().toString()).to.equal("tprv8gSy16H5hQ1MKNHzZDzsktr4aaGQSHg4XYVEbfsEiGSBcgw4J8dEm8uf19FH4L9h6W47VBKtc3bbYyjb6HAm6QdyRLpB6fsA7bW19RZnby2");
      });
    });
  });

  describe('#createWithMnemonic', () => {
    it('should create credentials with mnemonic', () => {
      const credential = new Credentials()
      const c = credential.createWithMnemonic('btc', 'livenet', '', 'en', 0);
      expect(c.mnemonic).to.equal(c.mnemonic);
      expect(c.mnemonic.split(' ').length).to.equal(12);
      expect(c.network).to.equal('livenet');
      expect(c.account).to.equal(0);
    });

    it('should assume derivation compliance on new credentials', () => {
      const credential = new Credentials()
      const c = credential.createWithMnemonic('btc', 'livenet', '', 'en', 0);
      expect(c.compliantDerivation).to.be.true;
      const xPrivKey = credential.getDerivedXPrivKey();
      expect(xPrivKey).to.equal(xPrivKey);
    });

    it('should create credentials with mnemonic (testnet)', () => {
      const credential = new Credentials()
      const c = credential.createWithMnemonic('btc', 'testnet', '', 'en', 0);
      expect(c.mnemonic).to.equal(c.mnemonic);
      expect(c.mnemonic.split(' ').length).to.equal(12);
      expect(c.network).to.equal('testnet');
    });

    it('should return and clear mnemonic', () => {
      const credential = new Credentials()
      const c = credential.createWithMnemonic('btc', 'testnet', '', 'en', 0);
      expect(c.mnemonic).to.equal(c.mnemonic);
      expect(credential.getMnemonic().split(' ').length).to.equal(12);
      credential.clearMnemonic();
      expect(credential.getMnemonic()).to.be.undefined;
    });
  });

  describe('#createWithMnemonic #fromMnemonic roundtrip', () => {
    _.each(['en', 'es', 'ja', 'zh', 'fr'], (lang) => {
      it('should verify roundtrip create/from with ' + lang + '/passphrase', () => {
        const credential = new Credentials()
        const c = credential.createWithMnemonic('btc', 'testnet', 'holamundo', lang, 0);
        expect(c.mnemonic).to.equal(c.mnemonic);
        let words = c.mnemonic;
        let xPriv = c.xPrivKey;
        let path = credential.getBaseAddressDerivationPath();

        const credential2 = new Credentials();
        const c2 = credential2.fromMnemonic('btc', 'testnet', words, 'holamundo', 0, 'BIP44');
        expect(c2.mnemonic).to.equal(c2.mnemonic);
        expect(words).to.equal(c2.mnemonic);
        expect(c2.xPrivKey).to.equal(c.xPrivKey);
        expect(c2.network).to.equal(c.network);
        expect(credential2.getBaseAddressDerivationPath()).to.equal(path);
      });
    });

    it('should fail roundtrip create/from with ES/passphrase with wrong passphrase', () => {
      const credential = new Credentials()
      const c = credential.createWithMnemonic('btc', 'testnet', 'holamundo', 'es', 0);
      expect(c.mnemonic).to.equal(c.mnemonic);
      let words = c.mnemonic;
      let xPriv = c.xPrivKey;
      let path = credential.getBaseAddressDerivationPath();

      const credential2 = new Credentials();
      const c2 = credential2.fromMnemonic('btc', 'testnet', words, 'chaumundo', 0, 'BIP44');
      expect(c2.network).to.equal(c.network);
      expect(credential2.getBaseAddressDerivationPath()).to.equal(path);
      expect(c2.xPrivKey).to.not.equal(c.xPrivKey);
    });
  });

  describe('Private key encryption', () => {
    describe('#encryptPrivateKey', () => {
      it('should encrypt private key and remove cleartext', () => {
        const credential = new Credentials()
        const c = credential.createWithMnemonic('btc', 'livenet', '', 'en', 0);
        credential.encryptPrivateKey('password');
        expect(credential.isPrivKeyEncrypted()).to.be.true;
        expect(c.xPrivKeyEncrypted).to.equal(c.xPrivKeyEncrypted);
        expect(c.mnemonicEncrypted).to.equal(c.mnemonicEncrypted);
        expect(c.xPrivKey).to.be.undefined;
        expect(c.mnemonic).to.be.undefined;
      });
      it('should fail to encrypt private key if already encrypted', () => {
        const credential = new Credentials()
        const c = credential.create('btc', 'livenet');
        credential.encryptPrivateKey('password');
        var err;
        try {
          credential.encryptPrivateKey('password');
        } catch (ex) {
          err = ex;
        }
        expect(err).to.equal(err);
      });
    });
    describe('#decryptPrivateKey', () => {
      it('should decrypt private key', () => {
        const credential = new Credentials()
        const c = credential.createWithMnemonic('btc', 'livenet', '', 'en', 0);
        credential.encryptPrivateKey('password');
        expect(credential.isPrivKeyEncrypted()).to.be.true;
        credential.decryptPrivateKey('password');
        expect(credential.isPrivKeyEncrypted()).to.be.false;
        expect(c.xPrivKey).to.equal(c.xPrivKey);
        expect(c.mnemonic).to.equal(c.mnemonic);
        expect(c.xPrivKeyEncrypted).to.be.undefined;
        expect(c.mnemonicEncrypted).to.be.undefined;
      });
      it('should fail to decrypt private key with wrong password', () => {
        const credential = new Credentials()
        const c = credential.createWithMnemonic('btc', 'livenet', '', 'en', 0);
        credential.encryptPrivateKey('password');

        var err;
        try {
          credential.decryptPrivateKey('wrong');
        } catch (ex) {
          err = ex;
        }
        expect(err).to.equal(err);
        expect(credential.isPrivKeyEncrypted()).to.be.true;
        expect(c.mnemonicEncrypted).to.equal(c.mnemonicEncrypted);
        expect(c.mnemonic).to.be.undefined;
      });
      it('should fail to decrypt private key when not encrypted', () => {
        const credential = new Credentials()
        const c = credential.create('btc', 'livenet');

        var err;
        try {
          credential.decryptPrivateKey('password');
        } catch (ex) {
          err = ex;
        }
        expect(err).to.equal(err);
        expect(credential.isPrivKeyEncrypted()).to.be.false;
      });
    });
    describe('#getKeys', () => {
      it('should get keys regardless of encryption', () => {
        const credential = new Credentials()
        const c = credential.createWithMnemonic('btc', 'livenet', '', 'en', 0);
        let keys = credential.getKeys();
        expect(keys).to.equal(keys);
        expect(keys.xPrivKey).to.equal(keys.xPrivKey);
        expect(keys.mnemonic).to.equal(keys.mnemonic);
        expect(keys.xPrivKey).to.equal(c.xPrivKey);
        expect(keys.mnemonic).to.equal(c.mnemonic);

        credential.encryptPrivateKey('password');
        expect(credential.isPrivKeyEncrypted()).to.be.true;
        let keys2 = credential.getKeys('password');
        expect(keys2).to.equal(keys2);
        expect(keys2).to.deep.equal(keys);

        credential.decryptPrivateKey('password');
        expect(credential.isPrivKeyEncrypted()).to.be.false;
        let keys3 = credential.getKeys();
        expect(keys3).to.equal(keys3);
        expect(keys3).to.deep.equal(keys);
      });
      it('should get derived keys regardless of encryption', () => {
        const credential = new Credentials()
        const c = credential.createWithMnemonic('btc', 'livenet', '', 'en', 0);
        let xPrivKey = credential.getDerivedXPrivKey();
        expect(xPrivKey).to.equal(xPrivKey);

        credential.encryptPrivateKey('password');
        expect(credential.isPrivKeyEncrypted()).to.be.true;
        let xPrivKey2 = credential.getDerivedXPrivKey('password');
        expect(xPrivKey2).to.equal(xPrivKey2);

        expect(xPrivKey2.toString('hex')).to.equal(xPrivKey.toString('hex'));

        credential.decryptPrivateKey('password');
        expect(credential.isPrivKeyEncrypted()).to.be.false;
        let xPrivKey3 = credential.getDerivedXPrivKey();
        expect(xPrivKey3).to.equal(xPrivKey3);
        expect(xPrivKey3.toString('hex')).to.equal(xPrivKey.toString('hex'));
      });
    });
  });
});
