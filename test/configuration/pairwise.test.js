const { expect } = require('chai');

const { Provider } = require('../../lib');

describe('Provider configuration', () => {
  it('validates subjectTypes members', () => {
    const throws = [
      () => {
        new Provider('http://localhost:3000', { // eslint-disable-line no-new
          subjectTypes: ['public', 'pairwise', 'foobar'],
        });
      },
      () => {
        new Provider('http://localhost:3000', { // eslint-disable-line no-new
          subjectTypes: ['foobar'],
        });
      },
    ];

    throws.forEach((fn) => {
      expect(fn).to.throw('only public and pairwise subjectTypes are supported');
    });
  });

  it('validates subjectTypes presence', () => {
    expect(() => {
      new Provider('http://localhost:3000', { // eslint-disable-line no-new
        subjectTypes: [],
      });
    }).to.throw('subjectTypes must not be empty');
  });
});
