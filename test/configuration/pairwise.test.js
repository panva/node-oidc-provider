import { expect } from 'chai';

import Provider from '../../lib/index.js';

describe('Provider configuration', () => {
  it('validates subjectTypes members', () => {
    const throws = [
      () => {
        new Provider('http://localhost:3000', {
          subjectTypes: ['public', 'pairwise', 'foobar'],
        });
      },
      () => {
        new Provider('http://localhost:3000', {
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
      new Provider('http://localhost:3000', {
        subjectTypes: [],
      });
    }).to.throw('subjectTypes must not be empty');
  });
});
