const User = require('../database/user.model');
const bcrypt = require('bcrypt');

const createUser = async ({
  firstName,
  lastName,
  email,
  password
}) => {

  const checkUserIfExist = await getUser({
    email,
  });

  if(checkUserIfExist) throw new Error('email used');

  const hashedPassword = await bcrypt.hashSync(password, Number(process.env.SALT_AMOUNT));


  await User.create({
    firstName,
    lastName,
    email,
    password: hashedPassword,
    userTypeId: 1,
  },);

  return true;
};

const getUserByCredentials = ({
  email,
}) => User.findOne({
  where: {
    email,
  }
});


const getUser = (params) => User.findOne({
  where: {
    ...params
  }
});

module.exports = {
  createUser,
  getUserByCredentials,
  getUser
};