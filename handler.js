'use strict';

const AWS = require('aws-sdk');
const crypto = require('crypto');
const { create, jsonMiddleware } = require('slspress');
const pem = require('pem')
const {X509Certificate} = require('crypto') 


pem.config({
    pathOpenSSL: '/usr/local/opt/openssl@1.1/bin/openssl' //replace with ur local openssl path
  })

// Configure the AWS SDK with credentials
AWS.config.update({
    accessKeyId: '',
    secretAccessKey: '',
    region: 'ap-southeast-1',
});

const s3 = new AWS.S3();
const dynamodb = new AWS.DynamoDB();

const handler = create();

handler.on('handle')
    .middleware(jsonMiddleware)
    .get('/hello-world', async (req, res) => {

        try {
            const bucketName = 'lambda-than-htut'; 
            const key = 'public-cert.pem'; 
            const tableName = 'test123';
        
            // Step 1: Read X.509 Certificate from S3
            const certificateData = await s3.getObject({ Bucket: bucketName, Key: key }).promise();
            const certificatePem = certificateData.Body.toString();
           
            // Step 2: Extract Public Key from Certificate
            const publicKey = await getPublicKey(certificatePem);
        
            // Step 3: Extract CommonName from Certificate Subject
            const commonName = extractCommonName(certificatePem);
            
            // Step 4: Generate Private Key using ECC algorithm
            const privateKey = generateECCPrivateKey();
            
            // Step 5: Sign the Public Key with the generated Private Key
            const signature = signPublicKey(publicKey, privateKey);
            
            // Step 6: Write encrypted content to DynamoDB
            await writeToDynamoDB(commonName, signature, tableName);
            
            return res.ok('hello-world');
          } catch (error) {
            console.error('Error:', error);
            return res.send({ statusCode: 500, body: 'Internal Server Error' });
          }
    });


function getPublicKey(certificatePem) {
    return new Promise((resolve, reject) => {
        pem.getPublicKey(certificatePem, (err, key) => {
        if (err) {
            reject(err);
        } else {
            resolve(key.publicKey);
        }
        });
    });
}
    
function extractCommonName(certificatePem) {
    // Implement the logic to extract CommonName from the certificate subject
    const x509 = new X509Certificate(certificatePem); 
    const value = x509.subject 

    // Define a regular expression to match the CN value
    const cnRegex = /CN=([^\/\s]+)/;

    // Use match to find the CN value
    const match = value.match(cnRegex);

    // Extract the CN value if there is a match
    const cnValue = match ? match[1] : null;

    return cnValue;
}
    
function generateECCPrivateKey() {
    // Choose the elliptic curve algorithm. Here we use 'prime256v1' curve.
    const curve = 'prime256v1';
    
    // Generate ECC key pair
    const { privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: curve,
    });
    
    // Export private key in PEM format
    const privateKeyPEM = privateKey.export({
        type: 'pkcs8',
        format: 'pem',
    });
    
    return privateKeyPEM;
}
    
function signPublicKey(publicKey, privateKey) {
    // Convert the public key to Buffer
    const publicKeyBuffer = Buffer.from(publicKey, 'utf-8');
    
    // Create a sign object using the private key
    const sign = crypto.createSign('SHA256');
    
    // Update the sign object with the public key data
    sign.update(publicKeyBuffer);
    
    // Sign the data with the private key
    const signature = sign.sign(privateKey, 'base64');
    
    return signature;
}    
    
async function writeToDynamoDB(commonName, signature, tableName) {
    // Implement the logic to write encrypted content to DynamoDB
    const params = {
        TableName: tableName,
        Item: {
        commonName: { S: commonName },
        signature: { S: signature },
        },
    };

    dynamodb.putItem(params, (err, data) => {
        if (err) {
        console.error('Error writing to DynamoDB:', err);
        } else {
        console.log('Successfully wrote to DynamoDB:', data);
        }
    });
 }
    
module.exports = handler.export();


