const { Model, DataTypes } = require('sequelize');

class Product extends Model {
  static init(connection) {
    super.init({
      title: {
        type: DataTypes.STRING(25),
        allowNull: false,
      },
      price: {
        type: DataTypes.INTEGER,
        allowNull: false,
      },
      expirationDate: {
        type: DataTypes.DATE,
        allowNull: false,
      }
    }, {
      sequelize: connection,
      modelName: 'products',
      timestamps: true,
    });
  }
}

module.exports = Product;