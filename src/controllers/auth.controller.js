const { checkUser } = require('../services/auth.service');
const AccountService = require('../services/user.service');

const login = async(req, res) => {
  const { email, password } = req.body;
  const token = await checkUser({ email, password });
  return res.json({ token });
};


const register = async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  await AccountService.createUser({ firstName, lastName, email, password });
  
  return res.json({ message: 'CREATED'});
};


module.exports = { 
  login, register
};


