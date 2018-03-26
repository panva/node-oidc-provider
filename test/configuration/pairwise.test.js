const { expect } = require('chai');
const Provider = require('../../lib');

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

  it('validates subjectTypes type', () => {
    expect(() => {
      new Provider('http://localhost:3000', { // eslint-disable-line no-new
        subjectTypes: 'public',
      });
    }).to.throw('subjectTypes must be an array');
  });

  it('validates pairwiseSalt presence when pairwise is configured', () => {
    const throws = [
      () => {
        new Provider('http://localhost:3000', { // eslint-disable-line no-new
          subjectTypes: ['pairwise'],
        });
      },
      () => {
        new Provider('http://localhost:3000', { // eslint-disable-line no-new
          subjectTypes: ['public', 'pairwise'],
        });
      },
    ];

    const notThrows = [
      () => {
        new Provider('http://localhost:3000', { // eslint-disable-line no-new
          subjectTypes: ['public'],
          pairwiseSalt: 'may be provided',
        });
      },
      () => {
        new Provider('http://localhost:3000', { // eslint-disable-line no-new
          subjectTypes: ['public'],
        });
      },
    ];

    throws.forEach((fn) => {
      expect(fn).to.throw(/pairwiseSalt must be configured/);
    });

    notThrows.forEach((fn) => {
      expect(fn).not.to.throw();
    });
  });
});
