import * as _ from 'lodash';

import {expect} from 'chai';
import 'mocha';

import {PayPro} from './paypro';

//var sinon = sinon || require('sinon');
const TestData = require('../test/testdata');

const TestDataBCH = _.clone(TestData.payProData);

//paypro is using C/H address for now
//TestDataBCH.toAddress = 'bchtest:qqkcn2tjp59v4xl24ercn99qdvdtz7qcvuvmw9knqf';

describe('Paypro', () => {
  let xhr, httpNode, headers;
  const pp = new PayPro();
  before(() => {
    // Stub time before cert expiration at Mar 27 2016
    //clock = sinon.useFakeTimers(1459105693843);

    xhr = {};
    headers = {};
    xhr.onCreate = req => {};
    xhr.open = (method, url) => {};
    xhr.setRequestHeader = (k, v) => {
      headers[k] = v;
    };
    xhr.getAllResponseHeaders = () => {
      return 'content-type: test';
    };
    xhr.send = () => {
      xhr.response = TestData.payProBuf;
      xhr.onload();
    };

    httpNode = {};
    httpNode.get = (opts, cb) => {
      var res: any = {};
      res.statusCode = httpNode.error || 200;
      if (httpNode.error == 404) res.statusMessage = 'Not Found';
      res.on = (e, cb) => {
        if (e == 'data') return cb(TestData.payProBuf);
        if (e == 'end') return cb();
      };
      return cb(res);
    };
    httpNode.request = (opts, cb) => {
      var res: any = {};
      res.statusCode = httpNode.error || 200;
      res.on = (e, cb) => {
        if (e == 'data') return cb(new Buffer('id'));
        if (e == 'end') return cb();
      };

      return cb(res);
    };
  });
  after(() => {
    //clock.restore();
  });

  it('should make a Payment Protocol request', done => {
    xhr.send = () => {
      xhr.response = 'id';
      xhr.onload();
    };

    xhr.statusText = null;
    pp.get(
      {
        url: 'http://an.url.com/paypro',
        httpNode: httpNode,
        env: 'node',
      },
      (err, res) => {
        expect(err).to.be.null;
        expect(res).to.deep.equal(TestData.payProData);
        done();
      },
    );
  });

  it('should make a Payment Protocol request with HTTP error', done => {
    httpNode.error = 404;
    pp.get(
      {
        url: 'http://an.url.com/paypro',
        httpNode: httpNode,
        env: 'node',
      },
      (err, res) => {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('HTTP Request Error: 404 Not Found ');
        done();
      },
    );
  });

  it('should create a Payment Protocol payment', () => {
    var data = TestData.payProData;
    var payment = pp.createPayment(
      data.merchant_data,
      '12ab1234',
      'mwRGmB4NE3bG4EbXJKTHf8uvodoUtMCRhZ',
      100,
      'btc',
    );
    var s = '';
    for (var i = 0; i < payment.length; i++) {
      s += payment[i].toString(16);
    }
    expect(s).to.equal(
      'a4c7b22696e766f6963654964223a22436962454a4a74473174394837374b6d4d3631453274222c226d65726368616e744964223a22444766754344656f66556e576a446d5537454c634568227d12412ab12341a1d864121976a914ae6eeec7e05624db748f9c16cce6fb53696ab3988ac',
    );
  });

  it('should send a PP payment (node)', done => {
    httpNode.error = null;
    var data = TestData.payProData;
    var opts = {
      merchant_data: data.merchant_data,
      rawTx: '12ab1234',
      refundAddr: 'mwRGmB4NE3bG4EbXJKTHf8uvodoUtMCRhZ',
      amountSat: 100,
      httpNode: httpNode,
      url: 'http://an.url.com/paypro',
      env: 'node',
    };
    var payment = pp.send(opts, (err, data) => {
      expect(err).to.be.null;
      done();
    });
  });
});
