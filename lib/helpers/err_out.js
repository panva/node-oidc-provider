module.exports = ({
  expose, message, error_description: description, scope,
}, state) => {
  if (expose) {
    return {
      error: message,
      ...(description !== undefined ? { error_description: description } : undefined),
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
