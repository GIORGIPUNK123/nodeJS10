const router = require('express').Router();

const productRoutes = require('./product.routes');
const authRoutes = require('./auth.routes');
const { checkAuth } = require('../middleware/auth.middleware');

router.use('/auth', authRoutes);
router.use(checkAuth);
router.use('/products', productRoutes);

module.exports = router;
