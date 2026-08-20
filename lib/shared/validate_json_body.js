export default function getValidateJsonBody(ErrorClass, errorDescription) {
  return async function validateJsonBody(ctx, next) {
    if (ctx.oidc.body === null
        || typeof ctx.oidc.body !== 'object'
        || Array.isArray(ctx.oidc.body)) {
      throw new ErrorClass(errorDescription);
    }

    return next();
  };
}
