import { Eta } from 'eta';

import layoutTemplate from './layout.js';
import loginTemplate from './login.js';
import interactionTemplate from './interaction.js';

let eta;

export const interaction = (locals) => {
  eta ||= new Eta({ useWith: true });
  return eta.renderString(interactionTemplate, locals);
};

export const layout = (locals) => {
  eta ||= new Eta({ useWith: true });
  return eta.renderString(layoutTemplate, locals);
};

export const login = (locals) => {
  eta ||= new Eta({ useWith: true });
  return eta.renderString(loginTemplate, locals);
};
