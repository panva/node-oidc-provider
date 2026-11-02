import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import isConstructable from '../../lib/helpers/type_validators.js';

describe('type validators helper', () => {
  it('should be falsy when argument is null', { timeout: 3000 }, () => {
    assert.equal(isConstructable(null), false);
  });

  it('should be falsy when argument is arrow function', { timeout: 3000 }, () => {
    assert.equal(isConstructable(() => {}), false);
  });

  it('should be successfull executed if argument is constructable', { timeout: 3000 }, () => {
    assert.equal(isConstructable(class {}), true);
    // biome-ignore lint/complexity/useArrowFunction: test intentionally uses a function expression to verify constructable detection
    assert.equal(isConstructable(function () {}), true);
  });
});
