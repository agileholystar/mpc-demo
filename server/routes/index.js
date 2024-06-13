const router = require('express').Router();

const {
    keygenStep1,
    keygenStep2,
} = require('../controllers/keygen.controller');
router.put('/keygen/step1', keygenStep1);
router.put('/keygen/step2', keygenStep2);

const { signStep1, signStep2 } = require('../controllers/sign.controller');
router.put('/sign/step1', signStep1);
router.put('/sign/step2', signStep2);

module.exports = router;
