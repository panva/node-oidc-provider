import { expect } from 'chai';

import postchangelog from '../../.postchangelog.cjs';

const { formatChangelog } = postchangelog;

describe('postchangelog formatting', () => {
  it('separates linked and unlinked second-level headings', () => {
    for (const newline of ['\n', '\r\n']) {
      const input = [
        '# Changelog',
        '',
        '### [2.0.0](new)',
        '',
        '### Fixes',
        '',
        '* fix',
        '## [1.0.0](old)',
        '',
        'details',
        '## Notes',
      ].join(newline);
      const expected = [
        '# Changelog',
        '',
        '## [2.0.0](new)',
        '',
        '### Fixes',
        '',
        '* fix',
        '',
        '## [1.0.0](old)',
        '',
        'details',
        '',
        '## Notes',
      ].join(newline);

      expect(formatChangelog(input)).to.equal(expected);
      expect(formatChangelog(expected)).to.equal(expected);
    }
  });
});
