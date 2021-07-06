const crypto = require('crypto');
const {performance} = require('perf_hooks');


console.log("Using Diffie Hellman")
console.log("");

var teacherKeyGenerationStart = performance.now();
const teacher= crypto.getDiffieHellman('modp15');
teacher.generateKeys();
var teacherKeyGenerationEnd = performance.now();
console.log(`time taken for 3072 bit teacher key generation: ${teacherKeyGenerationEnd - teacherKeyGenerationStart} ms`);

var studentKeyGenerationStart = performance.now();
const student = crypto.getDiffieHellman('modp15');

student.generateKeys();
var studentKeyGenerationEnd = performance.now();
console.log(`time taken for 3072 bit student key generation: ${studentKeyGenerationEnd - studentKeyGenerationStart} ms`);


var teacherSharedKeyCalculationStart = performance.now();
const teacherSharedKey = teacher.computeSecret(student.getPublicKey(),null,'hex');
var teacherSharedKeyCalculationEnd = performance.now();
console.log(`time taken for shared key calculation at teacher end: ${teacherSharedKeyCalculationEnd - teacherSharedKeyCalculationStart} ms`);

var studentSharedKeyCalculationStart = performance.now();
const studentSharedKey = student.computeSecret(teacher.getPublicKey(),null,'hex');
var studentSharedKeyCalculationEnd = performance.now();
console.log(`time taken for shared key calculation at student end: ${studentSharedKeyCalculationEnd - studentSharedKeyCalculationStart} ms`);



