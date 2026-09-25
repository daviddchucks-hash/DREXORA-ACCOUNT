const express = require('express');
const accountController = require('../controllers/account.controller');
const connectedAppsController = require('../controllers/connected-apps.controller');
const { authenticate } = require('../middleware/auth.middleware');

const router = express.Router();

router.use(authenticate); // Require valid session for all account endpoints

router.get('/profile', accountController.getProfile);
router.patch('/profile', accountController.updateProfile);
router.get('/sessions', accountController.getSessions);
router.delete('/sessions/:id', accountController.revokeSession);
router.post('/sessions/revoke-others', accountController.revokeOtherSessions);

// Connected Apps Endpoints
router.get('/connected-apps', connectedAppsController.getConnectedApps);
router.delete('/connected-apps/:clientId', connectedAppsController.revokeAppAccess);
router.post('/connected-apps/:clientId/revoke', connectedAppsController.revokeAppAccess);

// Account Deletion Endpoint
router.delete('/delete', accountController.deleteAccount);
router.post('/delete', accountController.deleteAccount);

module.exports = router;
