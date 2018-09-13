import * as _ from 'lodash';

import { expect } from 'chai';
import 'mocha';

import { Logger } from './log'

describe('Logs', () => {
  let originalLog;
  const log = new Logger();
  beforeEach(function() {
    console.warn = function () {};
    console.debug = function () {};
    console.error = function () {};
  });

  it('should log .warn', function() {
    log.setLevel('info');
    let a = log.warn('Hello');
    expect(a).to.equal('[warn] Hello');
  });

  it('should log .debug', function() {
    log.setLevel('debug');
    let a = log.debug('Hello');
    expect(a).to.equal('[debug] Hello');
  });

  it('should log .error', function() {
    log.setLevel('warn');
    let a = log.error('Hello');
    expect(a).to.equal('[error] Hello');
  });

  it('should not log anything', function() {
    log.setLevel('silent');
    let a = log.debug('Hello');
    expect(a).to.be.undefined;
  });

});
