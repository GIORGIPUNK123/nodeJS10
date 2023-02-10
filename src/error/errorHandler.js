const { ApiError } = require('./exceptions');


const errorHandler = (err, req, res, next) => {
  console.log(err);
  if(err instanceof ApiError){
    return res.status(err.code).json({ message: err.message});
  } else{ 
    return res.status(500).json({ message: 'internal server error, try again later' });
  }
};

module.exports = errorHandler;