import { render } from 'eta';

import layoutTemplate from './layout.js';
import loginTemplate from './login.js';
import interactionTemplate from './interaction.js';

export const interaction = (locals) => render(interactionTemplate, locals, { useWith: true });
export const layout = (locals) => render(layoutTemplate, locals, { useWith: true });
export const login = (locals) => render(loginTemplate, locals, { useWith: true });
