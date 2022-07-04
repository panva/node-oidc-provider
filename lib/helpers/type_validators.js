const hasPrototype = (target) => target.prototype !== null && typeof target.prototype === 'object';

const isContructor = (fn) => fn.constructor instanceof Function
  && fn.constructor.name !== undefined;

const isConstructable = (constructable) => constructable instanceof Function
      && hasPrototype(constructable)
      && isContructor(constructable.constructor);

module.exports = {
  isConstructable,
};
