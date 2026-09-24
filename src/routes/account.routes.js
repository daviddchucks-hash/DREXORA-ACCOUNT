const express = require('express');
const accountController = require('../controllers/account.controller');
const { authenticate } = require('../middleware/auth.middleware');

const router = express.Router();

router.use(authenticate); // Require valid session for all account endpoints

router.get('/profile', accountController.getProfile);
router.patch('/profile', accountController.updateProfile);
router.get('/sessions', accountController.getSessions);
router.delete('/sessions/:id', accountController.revokeSession);
router.post('/sessions/revoke-others', accountController.revokeOtherSessions);

module.exports = router;
