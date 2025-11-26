import { quantumResistantEncrypt, quantumResistantDecrypt, encryptPrivateKey, decryptPrivateKey } from 'qshield-js';

// === CONFIG ===
const API_BASE_URL = 'http://localhost:5000/api';

const mp = '';
const apiKey = '';

async function testEncrypt(){
    const phrase = document.getElementById('dp').value;
    const res1 = await createEncrypted(apiKey, phrase);
    console.log(res1);
    
}
window.testEncrypt = testEncrypt;


async function testDecrypt(){
    const phrase = document.getElementById('ep').value;
    const res1 = await createDecrypted(apiKey, phrase, mp);
    console.log(res1);
    
}
window.testDecrypt = testDecrypt;

async function createEncrypted(apiKey, text) {
  const publicKey = await getMyPublicKey(apiKey);
  const { encrypted_data } = await quantumResistantEncrypt(text, publicKey);

  return encrypted_data;
}


async function createDecrypted(apiKey, encrypted_text, masterPassword) {
    const encryptedPrivateKey = await getMyEpk(apiKey);
    const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
    const password = await quantumResistantDecrypt(encrypted_text, privateKeyB64);
    return password;
}


// === API CALLS ===

async function getMyPublicKey(apiKey) {
  const res = await fetch(`${API_BASE_URL}/qshield/public-key`, {
    method: 'GET',
    headers: { 'api_key': apiKey }
  });
  const { public_key } = await res.json();
  return public_key;
}

async function getMyEpk(apiKey) {
  const res = await fetch(`${API_BASE_URL}/qshield/epk`, {
    method: 'GET',
    headers: { 'api_key': apiKey }
  });
  const { encrypted_private_key } = await res.json();
  return encrypted_private_key;
}
