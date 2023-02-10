const { DataTypes, Model } = require('sequelize');

class User extends Model {
  static init(connection) {
    super.init({
      firstName: {
        type: DataTypes.STRING(50),
        allowNull: false,
      },
      lastName: {
        type: DataTypes.STRING(50),
        allowNull: false,
      },
      email: {
        type: DataTypes.STRING(50),
        allowNull: false,
      },
      password: {
        type: DataTypes.STRING(100),
        allowNull: false,
      }
    }, {
      sequelize: connection,
      modelName: 'users',
      timestamps: false, // by default is true
    });
  }
}

module.exports = User;