const { DataTypes, Model } = require('sequelize');

class UserType extends Model {
  static init(connection) {
    super.init({
      title: {
        type: DataTypes.TEXT(20),
        allowNull: false,
      }
    }, {
      sequelize: connection,
      modelName: 'usertypes',
    });
  }
}

module.exports = UserType;