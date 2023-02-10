const asyncController = fn => (req, res, next) => {
  return Promise.resolve(fn(req, res, next)).catch((e) => next(e));
};

module.exports = asyncController;