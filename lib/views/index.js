import { Eta } from 'eta/core'; // eslint-disable-line import/no-unresolved

import layoutTemplate from './layout.js';
import loginTemplate from './login.js';
import interactionTemplate from './interaction.js';

let eta;

export const interaction = (locals) => {
  eta ||= new Eta();
  return eta.render(interactionTemplate, locals);
};

export const layout = (locals) => {
  eta ||= new Eta();
  return eta.render(layoutTemplate, locals);
};

export const login = (locals) => {
  eta ||= new Eta();
  return eta.render(loginTemplate, locals);
};
