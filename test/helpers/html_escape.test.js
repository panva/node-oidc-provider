const { expect } = require('chai');

const htmlSafe = require('../../lib/helpers/html_safe');

describe('htmlSafe helper', () => {
  it('handles numbers', () => {
    expect(htmlSafe(1)).to.eql('1');
    expect(htmlSafe(1.1)).to.eql('1.1');
  });

  it('handles non finites', () => {
    expect(htmlSafe(NaN)).to.eql('');
    expect(htmlSafe(Infinity)).to.eql('');
    expect(htmlSafe(-Infinity)).to.eql('');
  });

  it('handles strings', () => {
    expect(htmlSafe('foobar&<>"\'')).to.eql('foobar&amp;&lt;&gt;&quot;&#39;');
    expect(htmlSafe('')).to.eql('');
  });

  it('handles booleans', () => {
    expect(htmlSafe(false)).to.eql('false');
    expect(htmlSafe(true)).to.eql('true');
  });

  it('handles the rest', () => {
    expect(htmlSafe(null)).to.eql('');
    expect(htmlSafe(undefined)).to.eql('');
  });
});
