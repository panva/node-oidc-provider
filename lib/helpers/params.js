import { strict as assert } from 'node:assert';

import omitBy from './_/omit_by.js';

const cache = new WeakMap();

export default function getParams(allowList) {
  if (!cache.has(allowList)) {
    assert(allowList, 'allowList must be present');

    const klass = class Params {
      constructor(params) {
        allowList.forEach((prop) => {
          this[prop] = params[prop] || undefined;
        });
      }

      toPlainObject() {
        return omitBy({ ...this }, (val) => typeof val === 'undefined');
      }
    };

    cache.set(allowList, klass);
  }

  return cache.get(allowList);
}
