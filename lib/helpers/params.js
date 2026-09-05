import { strict as assert } from 'node:assert';

import omitBy from './_/omit_by.js';

export default class Params {
  constructor(allowList, params) {
    assert(allowList, 'allowList must be present');
    allowList.forEach((prop) => {
      this[prop] = params[prop] || undefined;
    });
  }

  toPlainObject() {
    return omitBy({ ...this }, (val) => typeof val === 'undefined');
  }
}
