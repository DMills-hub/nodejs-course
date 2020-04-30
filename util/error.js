const throwError = (err) => {
    const error = new Error(err);
    error.httpStatusCode = 500;
    return error;
}

module.exports = throwError;