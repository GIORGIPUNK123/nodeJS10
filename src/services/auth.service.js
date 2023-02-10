const jwt = require('jsonwebtoken');
const UserService = require('./user.service');
const bcrypt = require('bcrypt');
const {
  NotFoundException,
  UnauthorizedException,
} = require('../error/exceptions');

const checkUser = async ({ email, password }) => {
  const user = await UserService.getUserByCredentials({ email });

  const passwordValidity = bcrypt.compareSync(password, user.password);

  if (!passwordValidity) throw new UnauthorizedException('incorrect password');

  if (user) {
    const secret = process.env.JWT_SECRET;
    const token = jwt.sign(
      {
        userId: user.id,
      },
      secret,
      {
        expiresIn: `${process.env.JWT_EXPIRATION_HOURS}h`,
      }
    );

    console.log('token is  ', token);

    return token;
  }

  throw new NotFoundException('user not found');
};

module.exports = {
  checkUser,
};
