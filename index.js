const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
const fs = require("fs");
const router= require('./routes/routes.js');
const express = require("express");
const upload = require("express-fileupload");
const splitFile = require("split-file");
const NodeRSA = require("node-rsa");
const eccHelper = require("ecc-crypto-helper");
const eccrypto = require("eccrypto");
const {performance} = require('perf_hooks');

var eccKeyPair = eccHelper.ecc256.generatePemKeyPair().then(keyPair =>{
	var eccPrivateKey= keyPair.privateKey;
	var eccPublicKey= keyPair.publicKey;
});

function dateFormat(date) {
    var dateString = date.toString();
    var formattedDateString =dateString.substr(0, dateString.lastIndexOf(':'));
  	return formattedDateString;
}

const AppendInitVect = require("./appendInitVector");
const { fail } = require("assert");
const app = express();

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
	upload({
		createParentPath: true,
	})
);
//setting templating engine
app.set('views', path.join(__dirname, './public/views'));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'ejs');


// Global Variables
const chunkSize = 1024 * 1024;
let keyArray = new Array();//upload path
let namesArray = new Array();//files names
let encKeyArray = new Array();// enc key
let decKeyArray = new Array();
let decNamesArray = new Array();//dec files name..part wise
let origFile;

const uploadFile = (file) => {
	return new Promise((resolve, reject) => {
		file.mv("./public/uploads/" + file.name, (err) => {
			if (err) reject(err);
			resolve("done");
		});
	});
};

function sign(x){
	const private_key = fs.readFileSync('keys/privateKey.pem', 'utf-8');

	// const privateKey = fs.readFileSync("privateKey.txt");
	// rsa_key.importKey(privateKey, "pkcs1-private-pem");

	// File/Document to be signed
	const doc = fs.readFileSync(x);

	// Signing
	const signer = crypto.createSign('RSA-SHA256');
	signer.write(doc);
	signer.end();

	// Returns the signature in output_format which can be 'binary', 'hex' or 'base64'
	const signature = signer.sign(private_key, 'base64')

	console.log('Digital Signature: ', signature);

	// Write signature to the file `signature.txt`
	fs.writeFileSync('signature.txt', signature);
	}

function verify(x){
			
		const public_key = fs.readFileSync('keys/publicKey.pem', 'utf-8');

		// Signature from sign.js
		const signature = fs.readFileSync('signature.txt', 'utf-8');

		// File to be signed
		const doc = fs.readFileSync(x);

		// Signing
		const verifier = crypto.createVerify('RSA-SHA256');
		verifier.write(doc);
		verifier.end();

		// Verify file signature ( support formats 'binary', 'hex' or 'base64')
		const result = verifier.verify(public_key, signature, 'base64');

		console.log('Digital Signature Verification : ' + result);
}

function generateKey(filePath, index) {
	const KEY = crypto.createHash("sha256").update(filePath).digest();
	let keyItem = new Object();
	keyItem.index = index;
	keyItem.key = KEY;
	keyArray.push(keyItem);
}

function encryptFile(filePath, index) {
	const initVector = crypto.randomBytes(16);
	const key = keyArray[index].key;
	let encFilePath = filePath + ".enc";
	const readStream = fs.createReadStream(filePath);
	const gzip = zlib.createGzip();
	const writeStream = fs.createWriteStream(encFilePath);

	const cipher = crypto.createCipheriv("aes256", key, initVector);
	const appendInitVect = new AppendInitVect(initVector);

	readStream.pipe(gzip).pipe(cipher).pipe(appendInitVect).pipe(writeStream);
	namesArray.push(encFilePath);
}

function decryptFile(encFilePath, decFilePath, index) {
	const readIV = fs.createReadStream(encFilePath, { end: 15 });
	let initVector;
	readIV.on("data", (chunk) => {
		initVector = chunk;
	});
	readIV.on("close", () => {
		const readStream = fs.createReadStream(encFilePath, { start: 16 });
		const unzip = zlib.createGunzip();
		const key = decKeyArray[index];
		const decipher = crypto.createDecipheriv("aes256", key, initVector);
		const writeStream = fs.createWriteStream(decFilePath);
		readStream.pipe(decipher).pipe(unzip).pipe(writeStream);
		decNamesArray.push(decFilePath);
	});
}

function bf_cipher(algorithm, key, buf ,cb){
	let encrypted = '';
	const cip = crypto.createCipher(algorithm, key);
	encrypted += cip.update(buf, 'binary', 'hex');
	encrypted += cip.final('hex');
	fs.writeFileSync('./public/uploads/new-enc-'+ origFile, encrypted);
	cb(encrypted);
}

function bf_decipher(algorithm, key, encrypted,cb){
	let decrypted = '';
	const decipher = crypto.createDecipher(algorithm, key);
	decrypted += decipher.update(encrypted, 'hex', 'binary');
	decrypted += decipher.final('binary');
	fs.writeFileSync('./public/uploads/dec-text-'+ origFile, decrypted);
	cb(decrypted);
	//console.log(cb(decrypted));
}

function cipherDecipherFile(filename,algorithm, key){
	fs.readFile(filename, 'utf-8',(err, data) => {
		if (err) throw err;
		const s1 = new Date();

		bf_cipher(algorithm, key,data,function(encrypted) {
			const s2 = new Date();
			console.log('cipher:'+algorithm+','+(s2-s1) +'ms');

			bf_decipher(algorithm, key,encrypted,function(txt){
				const s3 = new Date();
				console.log('decipher:'+ algorithm +',' + (s3-s2)+'ms');
				//console.log(txt);
			});
		});
	});
}

function generateEccKeys(){

}
app.post("/upload", async (req, res) => {
	var fileUploadStart = performance.now();
	try {
		if (!req.files) {
			res.status(400);
			res.send("File not uploaded");
		} else {
			origFile = req.files.upload.name;
			uploadFile(req.files.upload)
				.then(() => {
					let url = "./public/uploads/" + origFile;
					sign(url);
					splitFile
						.splitFileBySize(("./public/uploads/"+ req.files.upload.name), chunkSize)
						.then((names) => {
							names.forEach((fileLocation, index) => {
								generateKey(fileLocation, index);
								encryptFile(fileLocation, index);
								const algs = ['blowfish'];
								const key = 'privateKey.txt';
								let filename = "./public/uploads/"+ origFile;
								algs.forEach((name)=> {
									cipherDecipherFile(filename,name,key);
									});
							});
							//if(req.body.keyGeneration === "rsa"){
							   const rsa_key = new NodeRSA();
								const privateKey = fs.readFileSync("privateKey.txt");
								rsa_key.importKey(privateKey, "pkcs1-private-pem");
								keyArray.forEach((keyObject, index) => {
									let encData = rsa_key.encryptPrivate(Buffer.from(keyObject.key), "base64");
									encKeyArray.push(encData);
								});
							//}
							/*else
							{	var eccPrivateKey = eccrypto.generatePrivate();
								var eccPublicKey = eccrypto.getPublic(eccPrivateKey);
							
								keyArray.forEach((keyObject, index) => {
									let encData = eccrypto.encrypt(eccPublicKey, Buffer.from(keyObject.key)).then(function(encrypted) {
										// B decrypting the key and storing in the deckeyArray
										eccrypto.decrypt(eccPrivateKey, encrypted).then(function(plaintext) {
											decKeyArray.push(plaintext);d
										});
									encKeyArray.push(String(encData));
									console.log(String(encData));
									});
								});
							}*/
							
							fs.writeFileSync(origFile, encKeyArray[0], { encoding: "base64" });
							// let numOfParts = encKeyArray.length.toString() + "\n";
							// fs.appendFileSync("1", numOfParts);s
							// encKeyArray.forEach((encKey, index) => {
							// 	fs.appendFileSync("1", encKey.toString(), { encoding: "base64" });
							// 	fs.appendFileSync("1", "\n");
							// });
							// namesArray.forEach((filePath, index) => {
							// 	fs.appendFileSync("1", filePath + "\n");
							// });
							var fileUploadEnd = performance.now();
							console.log(`time taken for file `+origFile+` upload: ${fileUploadEnd - fileUploadStart} ms`);
							res.status(200);
							res.json({
								"success":"success"
							})						
						})
						.catch((err) => {
							console.log(err);
							res.status(500);
							res.send("Error splitting file");
							res.end();
						});
				})
				.catch((err) => {
					console.log(err);
					res.status(500);
					res.send("Error saving file");
					res.end();
				});
		}
	} catch (err) {
		res.status(500).send(err);
	}
});



app.post("/download", (req, res) => {
	
	var fileDownloadStart = performance.now();
	const publicKey = fs.readFileSync("publicKey.txt");
	const dec_rsa_key = new NodeRSA();
	dec_rsa_key.importKey(publicKey, "pkcs1-public-pem");
	const fileId = req.body.fileId.toString();
	const encryptedKey0 = fs.readFileSync(fileId, { encoding: "base64" });
	const decryptedKey0 = dec_rsa_key.decryptPublic(encryptedKey0);
	
	
	// decKeyArray.push(decryptedKey0);
	// let decryptedFileName = namesArray[0].split("/").pop().replace(".enc", "");
	// let decryptedFilePath = path.join(__dirname, "downloads", decryptedFileName);d
	// decryptFile(namesArray[0], decryptedFilePath, 0);
	// let decData = dec_rsa_key.decryptPublic(encKeyArray[i]);
	
	decKeyArray.push(decryptedKey0);
	let decryptedFileName = namesArray[0].split("\\").pop().replace(".enc", "");
	decryptedFileName = decryptedFileName.split("/")[3];
	let decryptedFilePath = "./public/z/" + decryptedFileName;
	console.log(decryptedFileName, decryptedFilePath);

	decryptFile(namesArray[0], decryptedFilePath, 0);

	for (let i = 1; i < encKeyArray.length; i++) {
		let decData = dec_rsa_key.decryptPublic(encKeyArray[i]);
		decKeyArray.push(decData);
		let decryptedFileName = namesArray[i].split("\\").pop().replace(".enc", "");
		decryptedFileName = decryptedFileName.split("/")[3];
		let decryptedFilePath = "./public/z/" + decryptedFileName;

		decryptFile(namesArray[i], decryptedFilePath, i);
	}
	
	let decryptedOutputFile = "./public/z/"+ origFile;
	var decryptedFileUrl = "./public/z/" + origFile;
	setTimeout(() => {
		splitFile
			.mergeFiles(decNamesArray, decryptedOutputFile)
			.then(() => {
				verify(decryptedFileUrl);
				var fileDownloadEnd = performance.now();
				console.log(`time taken for file `+origFile+` download: ${fileDownloadEnd - fileDownloadStart} ms`);
				res.download("./public/z/"+origFile,origFile);
				//res.status(200).send("Successfully decrypted file");
				
			})
			.catch((err) => {
				console.log(err);
				res.status(500).send("Error decrypting file");

			});
	}, 2000);
});
app.get('/etee', (req,res)=>{
	res.render('teacher_msg_form');
  })

app.get('/', (req,res)=>{
	res.render('index.ejs');
})
app.get('/teacherLogin', (req,res)=>{
	res.render('./teacher/login.ejs');
  })
app.get('/studentLogin', (req,res)=>{
	res.render('./student/login.ejs');
  })

app.get('/teacher', (req,res)=>{
	res.render('./teacher/index.ejs',{messages: temp});
})


var messages = [];
var temp=[];

var sharedKey = "3833bb429dda01eb83b10b07f0f3674539e136f7390722aabefd05582aba45f8";
app.get('/student',(req,res)=>{
    let msgs = [];
    messages.forEach(message =>{
        let msg = message.message;
        let created_at= message.created_at
        let student_payload = Buffer.from(msg, 'base64').toString('hex');
        let student_iv = student_payload.substr(0, 32);
        let student_encrypted = student_payload.substr(32, student_payload.length - 32 - 32);
        let student_auth_tag = student_payload.substr(student_payload.length - 32, 32);
        console.table({ student_iv, student_encrypted, student_auth_tag });
        try {
            const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            Buffer.from(sharedKey, 'hex'),
            Buffer.from(student_iv, 'hex')
        );
        decipher.setAuthTag(Buffer.from(student_auth_tag, 'hex'));
        let decrypted = decipher.update(student_encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        let msgObj = Object.assign({
            message: decrypted,
            created_at: created_at
        })
        msgs.push(msgObj);
        console.table({ DecyrptedMessage: decrypted });
        var msgDecryptionEnd = performance.now();
        } catch (error) {
        console.log(error.message);
        }           
    })
    res.render('./student/index.ejs', {messages: msgs});
})


app.post('/sendMsg', (req,res)=>{

    const MESSAGE = req.body.msg;
    console.log("Teacher wants to send this message: "+ MESSAGE);

    var msgEncryptionStart = performance.now();
    const IV = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    Buffer.from(sharedKey, 'hex'),
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

	var datime=new Date();
    let msgObj = Object.assign({},{
        message: payload64,
        created_at: dateFormat(datime)
	    })
	
    messages.push(msgObj);
    console.log(payload64);
    console.log(msgObj);


	let tempObject = Object.assign({},{
        message: MESSAGE,
        created_at: dateFormat(datime)
    })
	console.log("*************************");
	console.log(tempObject);

	temp.push(tempObject);

    /*db.models.messages.create({
        message: payload64
    }).then(message=>{
        console.log("successfully stored in the db"+message.message);
    })
    res.json({success: "success"});*/

    var msgEncryptionEnd = performance.now();
	res.json({ "Success": "Success"})

})


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
	console.log(`Server started on PORT ${PORT}`);
});

