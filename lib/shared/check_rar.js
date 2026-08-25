import { InvalidAuthorizationDetails, InvalidRequest } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';
import normalizeAuthorizationDetails from '../helpers/normalize_authorization_details.js';

export default async function checkRar(ctx, next) {
  const { params, client } = ctx.oidc;

  if (params.authorization_details !== undefined) {
    const { richAuthorizationRequests } = instance(ctx.oidc.provider).features;

    if (richAuthorizationRequests.enabled) {
      if (
        params.response_type?.split(' ').includes('code') === false
        || params.response_type?.split(' ').includes('token')
        || params.response_type === 'none'
      ) {
        throw new InvalidRequest('authorization_details parameter is not supported for this response_type');
      }

      let details;

      try {
        details = JSON.parse(params.authorization_details);
      } catch (cause) {
        throw new InvalidAuthorizationDetails(
          'could not parse the authorization_details parameter JSON',
          { cause },
        );
      }

      details = normalizeAuthorizationDetails(details, {
        ErrorConstructor: InvalidAuthorizationDetails,
        label: 'authorization_details parameter',
      });

      if (details === undefined) {
        params.authorization_details = undefined;
        return next();
      }

      let i = 0;
      for (const detail of details) {
        if (!Object.hasOwn(richAuthorizationRequests.types, detail.type)) {
          throw new InvalidAuthorizationDetails(`unsupported authorization details type value (authorization details index ${i})`);
        }
        const config = richAuthorizationRequests.types[detail.type];

        if (client.authorizationDetailsTypes?.includes(detail.type) === false) {
          throw new InvalidAuthorizationDetails(`authorization details type '${detail.type}' is not allowed for this client`);
        }

        await config.validate(ctx, detail, client);

        i++;
      }
    }
  }

  return next();
}
