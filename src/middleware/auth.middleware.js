const jwt = require('jsonwebtoken');
const { UnauthorizedException } = require('../error/exceptions');

const checkAuth = async (req, res, next) => {
  try { 
    let token = req.headers['authorization'];

    if(!token) throw new UnauthorizedException('user is not authenticated');
  
    token = token.split(' ')[1];

  
    let decodedToken;
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      console.log(err, decoded);
      if(err) {
        throw new UnauthorizedException('user is not authenticated');
      }
      decodedToken = decoded;
    });
  
    req.user = {
      userId: decodedToken.userId
    };

    next();

  } catch(e){
    next(e);
  }
}; 

module.exports = { checkAuth };