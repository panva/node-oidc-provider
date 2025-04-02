import { InvalidAuthorizationDetails, InvalidRequest } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';
import isPlainObject from '../helpers/_/is_plain_object.js';

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
      } catch (err) {
        throw new InvalidRequest('could not parse the authorization_details parameter JSON');
      }

      if (!Array.isArray(details)) {
        throw new InvalidRequest('authorization_details parameter should be a JSON array');
      }

      if (!details.length) {
        params.authorization_details = undefined;
        return next();
      }

      let i = 0;
      for (const detail of details) {
        if (!isPlainObject(detail)) {
          throw new InvalidRequest('authorization_details parameter members should be a JSON object');
        }

        if (typeof detail.type !== 'string' || !detail.type.length) {
          throw new InvalidAuthorizationDetails(`authorization_details parameter members' type attribute must be a non-empty string (authorization details index ${i})`);
        }

        const config = richAuthorizationRequests.types[detail.type];
        if (!config) {
          throw new InvalidAuthorizationDetails(`unsupported authorization details type value (authorization details index ${i})`);
        }

        if (client.authorizationDetailsTypes?.includes(detail.type) === false) {
          throw new InvalidAuthorizationDetails(`authorization details type '${detail.type}' is not allowed for this client`);
        }

        // check common data fields
        for (const field of ['locations', 'actions', 'datatypes', 'privileges']) {
          if (field in detail && (!Array.isArray(detail[field]) || detail[field].some((value) => typeof value !== 'string' || !value.length))) {
            throw new InvalidAuthorizationDetails(`'${field}' must be an array of non-empty strings (authorization details index ${i})`);
          }
        }
        if ('identifier' in detail && (typeof detail.identifier !== 'string' || !detail.identifier.length)) {
          throw new InvalidAuthorizationDetails(`'identifier' must be a non-empty string (authorization details index ${i})`);
        }

        await config.validate(ctx, detail, client);

        // eslint-disable-next-line no-plusplus
        i++;
      }
    }
  }

  return next();
}
