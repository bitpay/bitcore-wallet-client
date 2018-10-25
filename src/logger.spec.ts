import * as _ from 'lodash';

import {expect} from 'chai';
import 'mocha';

import {Logger} from './logger';

describe('Logs', () => {
  let originalLog;
  const log = new Logger();
  beforeEach(() => {
    console.warn = () => {};
    console.debug = () => {};
    console.error = () => {};
  });

  it('should log .warn', () => {
    log.setLevel('info');
    let a = log.warn('Hello');
    expect(a).to.equal('[warn] Hello');
  });

  it('should log .debug', () => {
    log.setLevel('debug');
    let a = log.debug('Hello');
    expect(a).to.equal('[debug] Hello');
  });

  it('should log .error', () => {
    log.setLevel('warn');
    let a = log.error('Hello');
    expect(a).to.equal('[error] Hello');
  });

  it('should not log anything', () => {
    log.setLevel('silent');
    let a = log.debug('Hello');
    expect(a).to.be.undefined;
  });
});
