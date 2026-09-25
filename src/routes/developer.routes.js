const express = require('express');
const developerController = require('../controllers/developer.controller');
const { authenticate } = require('../middleware/auth.middleware');

const router = express.Router();

router.use(authenticate); // Require authentication for developer portal endpoints

router.get('/scopes', developerController.getScopes);
router.get('/applications', developerController.getApplications);
router.post('/applications', developerController.createApplication);
router.get('/applications/:id', developerController.getApplicationById);
router.patch('/applications/:id', developerController.updateApplication);
router.post('/applications/:id/rotate-secret', developerController.rotateSecret);
router.delete('/applications/:id', developerController.deleteApplication);

module.exports = router;
