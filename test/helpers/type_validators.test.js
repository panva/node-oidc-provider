/* eslint-disable prefer-arrow-callback */
import { expect } from 'chai';

import isConstructable from '../../lib/helpers/type_validators.js';

describe('type validators helper', () => {
  it('should be falsy when argument is null', () => {
    expect(isConstructable(null)).to.be.false;
  });

  it('should be falsy when argument is arrow function', () => {
    expect(isConstructable(() => {})).to.be.false;
  });

  it('should be successfull executed if argument is constructable', () => {
    expect(isConstructable(class {})).to.be.true;
    expect(isConstructable(function () {})).to.be.true;
  });
});
