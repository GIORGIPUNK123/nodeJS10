class ApiError extends Error {
  constructor(code, message) { 
    super();
    this.code = code;
    this.message = message;
    Error.captureStackTrace(this, this.constructor);
  }
}

class NotFoundException extends ApiError {
  constructor(message){
    super(404, message);
  }
}

class InternalServerErrorException extends ApiError {
  constructor(message){
    super(500, message);
  }
}

class UnauthorizedException extends ApiError { 
  constructor(message){
    super(301, message);
  }
}

class BadRequestException extends ApiError { 
  constructor(message){
    super(403, message);
  }
}

module.exports = {
  ApiError,
  NotFoundException,
  InternalServerErrorException,
  UnauthorizedException,
  BadRequestException,
};