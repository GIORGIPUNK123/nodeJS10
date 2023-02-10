const { findProductById, findProducts, updateProduct, deleteProduct, createProduct } = require('../controllers/products.controller');

const router = require('express').Router();

// GET: api/products/:productId
router.get('/:productId', findProductById);

// GET: api/products/
router.get('/', findProducts);

// POST: api/products/ 
router.post('/', createProduct);

// PUT: api/products/1
router.put('/:productId', updateProduct);

// DELETE  .../:productId
router.delete('/:productId', deleteProduct);


module.exports = router;