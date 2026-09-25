const express = require('express');
const platformController = require('../controllers/platform.controller');
const { authenticate } = require('../middleware/auth.middleware');

const router = express.Router();

router.get('/products', platformController.getProducts);
router.get('/my-access', authenticate, platformController.getMyPlatformAccess);

module.exports = router;
