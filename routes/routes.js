'use strict'
const express=require('express');
const router=express.Router();
const endToEndEncryption = require("../controllers/endToEndEncryption")

router.post('/sendMsg',endToEndEncryption );

module.exports =router;