import ejs from 'ejs';

import layoutTemplate from './layout.js';
import loginTemplate from './login.js';
import interactionTemplate from './interaction.js';

export const interaction = ejs.compile(interactionTemplate);
export const layout = ejs.compile(layoutTemplate);
export const login = ejs.compile(loginTemplate);
