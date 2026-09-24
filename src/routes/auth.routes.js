const express = require('express');
const authController = require('../controllers/auth.controller');
const { authenticate, strictAuthLimiter } = require('../middleware/auth.middleware');

const router = express.Router();

// Public auth routes
router.post('/register', strictAuthLimiter, authController.register);
router.post('/login', strictAuthLimiter, authController.login);
router.post('/verify-email', authController.verifyEmail);
router.get('/verify-email', authController.verifyEmail);
router.post('/resend-verification', strictAuthLimiter, authController.resendVerification);
router.post('/forgot-password', strictAuthLimiter, authController.forgotPassword);
router.post('/reset-password', strictAuthLimiter, authController.resetPassword);
router.post('/confirm-email-change', authController.confirmEmailChange);

// Protected auth routes
router.get('/me', authenticate, authController.me);
router.post('/logout', authenticate, authController.logout);
router.post('/logout-all', authenticate, authController.logoutAll);
router.post('/change-password', authenticate, authController.changePassword);
router.post('/request-email-change', authenticate, authController.requestEmailChange);

module.exports = router;
