import merge from 'lodash/merge.js';

import * as errors from '../../lib/helpers/errors.js';
import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  clientCredentials: { enabled: true },
  resourceIndicators: {
    getResourceServerInfo(ctx, resourceIndicator) {
      const [, wl, format] = resourceIndicator.split(':');
      if (wl.includes('wl')) {
        return {
          scope: 'api:read api:write',
          accessTokenFormat: format || 'opaque',
        };
      }

      throw new errors.InvalidTarget();
    },
    defaultResource(ctx) {
      if (ctx.oidc.body?.nodefault) {
        return undefined;
      }

      return 'urn:wl:opaque:default';
    },
  },
});

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['client_credentials'],
    response_types: [],
    redirect_uris: [],
  },
};
