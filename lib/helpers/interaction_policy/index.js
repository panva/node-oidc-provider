import Check from './check.js';
import Prompt from './prompt.js';
import login from './prompts/login.js';
import consent from './prompts/consent.js';

const base = () => {
  const DEFAULT = [];

  DEFAULT.get = function getPrompt(name) {
    if (typeof name !== 'string') {
      throw new TypeError('name must be a string');
    }
    return this.find((p) => p.name === name);
  };

  DEFAULT.remove = function removePrompt(name) {
    if (typeof name !== 'string') {
      throw new TypeError('name must be a string');
    }
    const i = this.findIndex((p) => p.name === name);
    this.splice(i, 1);
  };

  DEFAULT.clear = function clearAll() {
    while (this.length) {
      this.splice(0, 1);
    }
  };

  DEFAULT.add = function addPrompt(prompt, i = this.length) {
    if (!(prompt instanceof Prompt)) {
      throw new TypeError('argument must be an instance of Prompt');
    }
    this.splice(i, 0, prompt);
  };

  DEFAULT.add(login());
  DEFAULT.add(consent());

  return DEFAULT;
};

export { Check, Prompt, base };
