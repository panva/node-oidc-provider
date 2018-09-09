const { expect } = require('chai');

const { captureConsoleInfo, captureConsoleWarn } = require('../capture_output');
const attention = require('../../lib/helpers/attention');

describe('attention helper', () => {
  context('not in a TTY', () => {
    it('has a working method info', () => {
      const f = function () { attention.info('a message'); };
      const stderr = captureConsoleInfo(f);
      expect(stderr).to.equal('NOTICE: a message\n');
    });

    it('has a working method warn', () => {
      const f = function () { attention.warn('a message'); };
      const stderr = captureConsoleWarn(f);
      expect(stderr).to.equal('WARNING: a message\n');
    });
  });

  context('in a TTY', () => {
    it('has a working method info with color', () => {
      const f = function () { attention.info('a message'); };
      const stderr = captureConsoleInfo(f, true);
      expect(stderr).to.equal('\x1b[33;1mNOTICE: a message\x1b[0m\n');
    });

    it('has a working method warn with color', () => {
      const f = function () { attention.warn('a message'); };
      const stderr = captureConsoleWarn(f, true);
      expect(stderr).to.equal('\x1b[31;1mWARNING: a message\x1b[0m\n');
    });
  });
});
