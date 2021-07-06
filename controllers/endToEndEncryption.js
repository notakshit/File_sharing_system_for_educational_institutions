'use strict'
const crypto = require('crypto');
const {performance} = require('perf_hooks');


const sendEndToEndEncryptedMsg = (req, res) =>{

var teacherKeyGenerationStart = performance.now();
const teacher = crypto.createECDH('secp256k1');
teacher.generateKeys();
var teacherKeyGenerationEnd = performance.now();
console.log(`time taken for 256 bit teacher key generation: ${teacherKeyGenerationEnd - teacherKeyGenerationStart} ms`);

var studentKeyGenerationStart = performance.now();
const student = crypto.createECDH('secp256k1');
student.generateKeys();
var studentKeyGenerationEnd = performance.now();
console.log(`time taken for 256 bit student key generation: ${studentKeyGenerationEnd - studentKeyGenerationStart} ms`);



const teacherPublicKeyBase64 = teacher.getPublicKey().toString('base64');
const studentPublicKeyBase64 = student.getPublicKey().toString('base64');

var teacherSharedKeyCalculationStart = performance.now();
const teacherSharedKey = teacher.computeSecret(studentPublicKeyBase64, 'base64', 'hex');
var teacherSharedKeyCalculationEnd = performance.now();
console.log(`time taken for shared key calculation at teacher end: ${teacherSharedKeyCalculationEnd - teacherSharedKeyCalculationStart} ms`);

var studentSharedKeyCalculationStart = performance.now();
const studentSharedKey = student.computeSecret(teacherPublicKeyBase64, 'base64', 'hex');
var studentSharedKeyCalculationEnd = performance.now();
console.log(`time taken for shared key calculation at student end: ${studentSharedKeyCalculationEnd - studentSharedKeyCalculationStart} ms`);


console.log(teacherSharedKey === studentSharedKey);
console.log('Teacher shared Key: ', teacherSharedKey);
console.log('Student shared Key: ', studentSharedKey);

//teacher wants to send a remark/doubt to a particular student

const MESSAGE = req.body.msg;
console.log("Teacher wants to send this message: "+ MESSAGE);

var msgEncryptionStart = performance.now();
const IV = crypto.randomBytes(16);
const cipher = crypto.createCipheriv(
  'aes-256-gcm',
  Buffer.from(teacherSharedKey, 'hex'),
  IV
);

let encrypted = cipher.update(MESSAGE, 'utf8', 'hex');
encrypted += cipher.final('hex');

const auth_tag = cipher.getAuthTag().toString('hex');

console.table({
  IV: IV.toString('hex'),
  encrypted: encrypted,
  auth_tag: auth_tag
});

const payload = IV.toString('hex') + encrypted + auth_tag;

const payload64 = Buffer.from(payload, 'hex').toString('base64');
console.log(payload64);

var msgEncryptionEnd = performance.now();



//student will get the payload and decrypt the message from here

var msgDecryptionStart = performance.now();

const student_payload = Buffer.from(payload64, 'base64').toString('hex');

const student_iv = student_payload.substr(0, 32);
const student_encrypted = student_payload.substr(32, student_payload.length - 32 - 32);
const student_auth_tag = student_payload.substr(student_payload.length - 32, 32);

console.table({ student_iv, student_encrypted, student_auth_tag });

try {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    Buffer.from(studentSharedKey, 'hex'),
    Buffer.from(student_iv, 'hex')
  );

  decipher.setAuthTag(Buffer.from(student_auth_tag, 'hex'));

  let decrypted = decipher.update(student_encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  console.table({ DecyrptedMessage: decrypted });

  var msgDecryptionEnd = performance.now();
  console.log(`time taken for msg encryption: ${msgEncryptionEnd - msgEncryptionStart} ms`);
  console.log(`time taken for msg decryption: ${msgDecryptionEnd - msgDecryptionStart} ms`);

  res.render('student_msg_received.ejs', {decryptedMessage: decrypted, studentIV: student_iv, studentEncryptedMsg: student_encrypted, studentAuthTag: student_auth_tag});
} catch (error) {
  console.log(error.message);
}
}

module.exports = sendEndToEndEncryptedMsg