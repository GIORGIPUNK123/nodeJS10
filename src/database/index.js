const { Sequelize } = require('sequelize');

const Product = require('./product.model');
const User = require('./user.model');
const UserType = require('./userType.model');

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USERNAME,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: 'postgres',
    port: 5432,
    logging: false,
  }
);

Product.init(sequelize);
User.init(sequelize);
UserType.init(sequelize);

(async () => {
  try {
    await sequelize.authenticate();
    console.log('Connection has been established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
})();


UserType.hasMany(User, {
  foreignKey: {
    name: 'userTypeId',
    allowNull: false
  }
});

User.belongsTo(UserType, {
  foreignKey: {
    name: 'userTypeId',
    allowNull: false
  }
});

(async () => {
  // force: false -> ნიშნავს, რომ თეიბლი არსებობს მონაცემთა ბაზაში და არ წაშალოს და თავიდან არ შექმნას

  // alter: true -> ნიშნავს, რომ თუ რაიმე ახალი ფილდი ან ცვლილება გვაქვს რომელიმე ფილდში გადააკეთოს მონაცეთა ბაზაშიც 

  await Product.sync({ force: false }).catch((e) => console.error('models:products:error', e));

  await User.sync({ force: false }).catch((e) => console.error('models:users:error', e));

  await UserType.sync({ force: false }).catch((e) => console.error('models:userTypes:error', e));
})();


module.exports = sequelize;


