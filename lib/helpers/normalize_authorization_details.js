import isPlainObject from './_/is_plain_object.js';

const ARRAY_FIELDS = ['locations', 'actions', 'datatypes', 'privileges'];

export default function normalizeAuthorizationDetails(details, {
  ErrorConstructor = TypeError,
  label = 'authorization details policy result',
} = {}) {
  if (details === undefined || (Array.isArray(details) && details.length === 0)) {
    return undefined;
  }

  if (!Array.isArray(details)) {
    throw new ErrorConstructor(`${label} should be a JSON array`);
  }

  let i = 0;
  for (const detail of details) {
    if (!isPlainObject(detail)) {
      throw new ErrorConstructor(`${label} members should be a JSON object`);
    }

    if (
      !Object.hasOwn(detail, 'type')
      || typeof detail.type !== 'string'
      || !detail.type.length
    ) {
      throw new ErrorConstructor(`${label} members' type attribute must be a non-empty string (authorization details index ${i})`);
    }

    for (const field of ARRAY_FIELDS) {
      if (
        field in detail
        && (
          !Array.isArray(detail[field])
          || detail[field].some((value) => typeof value !== 'string' || !value.length)
        )
      ) {
        throw new ErrorConstructor(`'${field}' must be an array of non-empty strings (authorization details index ${i})`);
      }
    }

    if (
      'identifier' in detail
      && (typeof detail.identifier !== 'string' || !detail.identifier.length)
    ) {
      throw new ErrorConstructor(`'identifier' must be a non-empty string (authorization details index ${i})`);
    }

    i++;
  }

  return details;
}
