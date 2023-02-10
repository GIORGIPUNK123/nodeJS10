const Product = require('../database/product.model');

const Log = require('../mongoDb/schemas/log.schema');

const {
  BadRequestException,
  NotFoundException,
} = require('../error/exceptions');

const findProductById = (productId) => Product.findByPk(productId);

const findProducts = () => Product.findAll();

const createProduct = async ({
  title,
  amount,
  price,
  expirationDate,
  userId,
}) => {
  if (!title || !amount || !price)
    throw new BadRequestException('all field are required');

  if (price < 0) throw new BadRequestException('price must not be less than 0');

  const productInDb = await Product.findOne({
    where: {
      title,
    },
  });

  if (productInDb) throw new BadRequestException('product already exist');

  await Product.create({
    title,
    amount,
    price,
    userId,
    expirationDate,
  });

  return 'CREATED';
};

const updateProduct = async ({ id, title, amount, price, userId }) => {
  const product = await Product.findByPk(id);

  // TODO: notfound
  if (!product) throw new NotFoundException('product not found ');

  await Product.update(
    {
      title,
      amount,
      price,
    },
    {
      where: {
        id,
      },
    }
  );

  if (product.title !== title) {
    const log = new Log({
      actionType: 'updated',
      changedField: 'title',
      previousValue: product.title,
      currentValue: title,
      userId,
    });
    await log.save();
  }

  if (product.price !== price) {
    const log = new Log({
      actionType: 'updated',
      changedField: 'title',
      previousValue: product.title,
      currentValue: title,
      userId,
    });
    await log.save();
  }

  return 'UPDATED';
};

const deleteProduct = async ({ productId, userId }) => {
  // const product = await Product.findByPk(productId);

  const product = await Product.create({
    title: 'test',
    price: 1234,
    expirationDate: new Date(),
    userId: 5,
  });

  // if (!product || product.userId !== userId ) throw new NotFoundException('product not found');

  await Product.destroy({
    where: {
      id: product.id,
    },
  });

  const logAboutDelete = new Log({
    actionType: 'deleted',
    userId,
  });

  await logAboutDelete.save();

  return 'DELETED';
};

module.exports = {
  findProductById,
  findProducts,
  createProduct,
  updateProduct,
  deleteProduct,
};
