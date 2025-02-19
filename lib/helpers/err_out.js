export default ({
  expose, message, error_description: description, error_detail: detail, scope,
}, state) => {
  if (expose) {
    return {
      error: message,
      ...(description !== undefined ? { error_description: description } : undefined),
      ...(detail !== undefined ? { error_detail: detail } : undefined),
      ...(scope !== undefined ? { scope } : undefined),
      ...(state !== undefined ? { state } : undefined),
    };
  }
  return {
    error: 'server_error',
    error_description: 'oops! something went wrong',
    ...(state ? { state } : undefined),
  };
};
