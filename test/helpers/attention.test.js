import { expect } from 'chai';

import { captureConsoleInfo, captureConsoleWarn } from '../capture_output.js';
import * as attention from '../../lib/helpers/attention.js';

describe('attention helper', () => {
  context('not in a TTY', () => {
    it('has a working method info', () => {
      const f = function () { attention.info('a message'); };
      const stderr = captureConsoleInfo(f);
      expect(stderr).to.equal('oidc-provider NOTICE: a message\n');
    });

    it('has a working method warn', () => {
      const f = function () { attention.warn('a message'); };
      const stderr = captureConsoleWarn(f);
      expect(stderr).to.equal('oidc-provider WARNING: a message\n');
    });
  });

  context('in a TTY', () => {
    it('has a working method info with color', () => {
      const f = function () { attention.info('a message'); };
      const stderr = captureConsoleInfo(f, true);
      expect(stderr).to.equal('\x1b[33;1moidc-provider NOTICE: a message\x1b[0m\n');
    });

    it('has a working method warn with color', () => {
      const f = function () { attention.warn('a message'); };
      const stderr = captureConsoleWarn(f, true);
      expect(stderr).to.equal('\x1b[31;1moidc-provider WARNING: a message\x1b[0m\n');
    });
  });
});
