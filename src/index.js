import { quantumResistantEncrypt, quantumResistantDecrypt, encryptPrivateKey, decryptPrivateKey } from 'qshield-js';
import detectEthereumProvider from "@metamask/detect-provider";
import Web3 from "web3";
import * as ethers from "ethers";
import artifact30 from "./QshieldLeaderboard.json";
import artifact50 from "./QshieldLeaderboard2.json";
import artifact_messenger from "./QshieldMessenger.json";
import artifact_desci from "./QshieldDescivault.json";

// === CONFIG ===
const API_BASE_URL = 'https://quantumsure.onrender.com/api';
//const API_BASE_URL = 'http://localhost:5000/api';

const mp = 'shield';
const apiKey = '9661764145784228459';

async function testEncrypt(){
    const phrase = document.getElementById('dp').value;
    const res1 = await createEncrypted(apiKey, phrase);
    localStorage.setItem("edata", res1.toString());
    const d = localStorage.getItem("edata");
    console.log(d);
    
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
  //console.log(publicKey);
  const { encrypted_data } = await quantumResistantEncrypt(text, publicKey);

  return encrypted_data;
}


async function createDecrypted(apiKey, encrypted_text, masterPassword) {
    const encryptedPrivateKey = await getMyEpk(apiKey);
    console.log(masterPassword);
    const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
    console.log(privateKeyB64);
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

// contract

async function testFetch() {
    const acc = localStorage.getItem("acc");
    const web3 = new Web3(window.ethereum);
    var abiInstance = artifact30.abi;
    var contract = new web3.eth.Contract(abiInstance, "0x6CeE2EbDA4512a6b5dAC74d3FCb0BBf4b9a7910C");




  try  {
    var res1 = await contract.methods['getScore']().call({from: acc});
    console.log(res1)
  }
  catch (err){
    console.log(err);
  }



}
window.testFetch = testFetch;


async function testSubmit() {
    const acc = localStorage.getItem("acc");
    const web3 = new Web3(window.ethereum);
    var abiInstance = artifact30.abi;
    const d = localStorage.getItem("edata");
    const cid = await web3.eth.getChainId();


    var contract = new web3.eth.Contract(abiInstance, "0x6CeE2EbDA4512a6b5dAC74d3FCb0BBf4b9a7910C");
    const res = await fetch(`${API_BASE_URL}/qshield/sign`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json'  },
    body: JSON.stringify({
      data: { playerAddress: acc, identifier: d, score: 100, chainId: cid }
    }),
    });

    const vals = await res.json();

    const vhex = web3.utils.toHex(vals.v);

    const hashFromFrontend = web3.utils.soliditySha3(
    { type: 'address', value: acc },
    { type: 'string', value: d },
    { type: 'uint256', value: 100},
    { type: 'uint256', value: vals.nonce },
    { type: 'uint256', value: cid }
    );

    const recovered = web3.eth.accounts.recover(hashFromFrontend, vhex, vals.r, vals.s);
    console.log("Recovered signer address:", recovered);

    const recovered2 = web3.eth.accounts.recover(vals.hash, vhex, vals.r, vals.s);
    console.log("Recovered signer address 2:", recovered2);


    var gasEst = BigInt(100000);
    var gasPriceEst = BigInt(10);




    try {
      gasEst = await contract.methods.submitScore(d, 100, Number(vals.nonce), Number(vals.v), vals.r, vals.s).estimateGas({from: acc});
      gasEst = (BigInt(2) * gasEst)/BigInt(1);
      gasPriceEst = await web3.eth.getGasPrice();
      gasPriceEst = (BigInt(2) * gasPriceEst)/BigInt(1);
    }
    catch (err){
      console.log(err);
      return;
    }


  contract.methods.submitScore(d, 100, Number(vals.nonce), Number(vals.v), vals.r, vals.s)
    .send({from: acc, gas: gasEst, gasPrice: gasPriceEst})
    .catch((error) => {
        console.error('Call Error:', error);
        return;
    });



}
window.testSubmit = testSubmit;


async function testFetch2() {
    const acc = localStorage.getItem("acc");
    const web3 = new Web3(window.ethereum);
    var abiInstance = artifact_messenger.abi;
    var contract = new web3.eth.Contract(abiInstance, "0x3F8a211749020bfb29657be10db3EA19bBD67F86");




  try  {
    var res1 = await contract.methods['getTotalMessages']().call({from: acc});
    console.log(res1)
  }
  catch (err){
    console.log(err);
  }



}
window.testFetch2 = testFetch2;


async function testSubmit2() {
    const acc = localStorage.getItem("acc");
    const recipient = '0xd2321B9E34C928a475f25eb37327AEEcf0962E6c';
    const web3 = new Web3(window.ethereum);
    var abiInstance = artifact_messenger.abi;
    const d = localStorage.getItem("edata");
    const cid = await web3.eth.getChainId();


    var contract = new web3.eth.Contract(abiInstance, "0x3F8a211749020bfb29657be10db3EA19bBD67F86");
    const res = await fetch(`${API_BASE_URL}/qshield/sign/msg`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json'  },
    body: JSON.stringify({
      data: { senderAddress: acc, recipientAddress: recipient, chainId: cid }
    }),
    });

    const vals = await res.json();

    const vhex = web3.utils.toHex(vals.v);

    const hashFromFrontend = web3.utils.soliditySha3(
    { type: 'address', value: acc },
    { type: 'address', value: recipient },
    { type: 'uint256', value: vals.nonce + 1},
    { type: 'uint256', value: vals.nonce },
    { type: 'uint256', value: cid }
    );



    const recovered = web3.eth.accounts.recover(hashFromFrontend, vhex, vals.r, vals.s);
    console.log("Recovered signer address:", recovered);

    const recovered2 = web3.eth.accounts.recover(vals.hash, vhex, vals.r, vals.s);
    console.log("Recovered signer address 2:", recovered2);



    var gasEst = BigInt(100000);
    var gasPriceEst = BigInt(10);





    try {
      gasEst = await contract.methods.sendMessage(recipient, d, Number(vals.nonce), Number(vals.v), vals.r, vals.s).estimateGas({from: acc});
      gasEst = (BigInt(2) * gasEst)/BigInt(1);
      gasPriceEst = await web3.eth.getGasPrice();
      gasPriceEst = (BigInt(2) * gasPriceEst)/BigInt(1);
    }
    catch (err){
      console.log(err);
      return;
    }


  contract.methods.sendMessage(recipient, d, Number(vals.nonce), Number(vals.v), vals.r, vals.s)
    .send({from: acc, gas: gasEst, gasPrice: gasPriceEst})
    .catch((error) => {
        console.error('Call Error:', error);
        return;
    });



}
window.testSubmit2 = testSubmit2;


async function testCreate3() {
    const acc = localStorage.getItem("acc");
    const web3 = new Web3(window.ethereum);
    var abiInstance = artifact_desci.abi;
    const cid = await web3.eth.getChainId();


    var contract = new web3.eth.Contract(abiInstance, "0x9D27B112112a8452CEEc55D1CB71EB45551b019d");
    



    var gasEst = BigInt(100000);
    var gasPriceEst = BigInt(10);





    try {
      gasEst = await contract.methods.createProject("test project", "just a test").estimateGas({from: acc});
      gasEst = (BigInt(2) * gasEst)/BigInt(1);
      gasPriceEst = await web3.eth.getGasPrice();
      gasPriceEst = (BigInt(2) * gasPriceEst)/BigInt(1);
    }
    catch (err){
      console.log(err);
      
      
    }
    
    

  const pid = contract.methods.createProject("test project", "just a test")
    .send({from: acc, gas: gasEst, gasPrice: gasPriceEst})
    .catch((error) => {
        console.error('Call Error:', error);
        return;
    });
    
    console.log(pid);



}
window.testCreate3 = testCreate3;



async function testFetch3() {
    const acc = localStorage.getItem("acc");
    const web3 = new Web3(window.ethereum);
    var abiInstance = artifact_desci.abi;
    var contract = new web3.eth.Contract(abiInstance, "0x9D27B112112a8452CEEc55D1CB71EB45551b019d");




  try  {
    var res1 = await contract.methods['getEntry'](0).call({from: acc});
    console.log(res1)
  }
  catch (err){
    console.log(err);
  }



}
window.testFetch3 = testFetch3;


async function testSubmit3() {
    const acc = localStorage.getItem("acc");
    const pid = 1;
    const web3 = new Web3(window.ethereum);
    var abiInstance = artifact_desci.abi;
    const d = localStorage.getItem("edata");
    const cid = await web3.eth.getChainId();


    var contract = new web3.eth.Contract(abiInstance, "0x9D27B112112a8452CEEc55D1CB71EB45551b019d");
    
    const res = await fetch(`${API_BASE_URL}/qshield/sign/desci`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json'  },
    body: JSON.stringify({
      data: { callerAddress: acc, submissionHash: web3.utils.keccak256(d), projectId: pid, chainId: cid }
    }),
    });

    const vals = await res.json();

    const vhex = web3.utils.toHex(vals.v);
    
    const hashFromFrontend = web3.utils.soliditySha3(
    { type: 'address', value: acc },
    { type: 'bytes32', value: web3.utils.keccak256(d) },
    { type: 'uint256', value: pid},
    { type: 'uint256', value: vals.nonce },
    { type: 'uint256', value: cid }
    );



    const recovered = web3.eth.accounts.recover(hashFromFrontend, vhex, vals.r, vals.s);
    console.log("Recovered signer address:", recovered);

    const recovered2 = web3.eth.accounts.recover(vals.hash, vhex, vals.r, vals.s);
    console.log("Recovered signer address 2:", recovered2);

    const data = {
        encryptedBlob: d,
        projectId: pid,
        cid: "010101",
        title: "First Entry",
        isPublic: true,
        doi: "01",
        tags: ["Test", "QA"]
    }

    var gasEst = BigInt(100000);
    var gasPriceEst = BigInt(10);





    try {
      gasEst = await contract.methods.submitData(data, Number(vals.nonce), Number(vals.v), vals.r, vals.s).estimateGas({from: acc});
      gasEst = (BigInt(2) * gasEst)/BigInt(1);
      gasPriceEst = await web3.eth.getGasPrice();
      gasPriceEst = (BigInt(2) * gasPriceEst)/BigInt(1);
    }
    catch (err){
      console.log(err);
      
    }


  contract.methods.submitData(data, Number(vals.nonce), Number(vals.v), vals.r, vals.s)
    .send({from: acc, gas: gasEst, gasPrice: gasPriceEst})
    .catch((error) => {
        console.error('Call Error:', error);
        return;
    });



}
window.testSubmit3 = testSubmit3;


// metamask

async function connectOrDisconnect() {
    const acc_cur = localStorage.getItem("acc") || "";
    console.log(acc_cur);
    if (acc_cur != "" && acc_cur != null){
        localStorage.setItem("acc","");
        document.getElementById("login-status").textContent = "Login";
        return;
    }

    var chainId = 13337;
    var cid = '0x3419';
    var chain = 'Beam Testnet';
    var name = 'Beam Testnet';
    var symbol = 'BEAM';
    var rpc = "https://build.onbeam.com/rpc/testnet";

    const provider = await detectEthereumProvider()
    console.log(window.ethereum);
    if (provider && provider === window.ethereum) {
        console.log("MetaMask is available!");

        console.log(window.ethereum.networkVersion);
        if (window.ethereum.networkVersion !== chainId) {
            try {
                await window.ethereum.request({
                    method: 'wallet_switchEthereumChain',
                    params: [{ chainId: cid }]
                });
                console.log("changed to ".concat(name).concat(" successfully"));

            } catch (err) {
                console.log(err);
                // This error code indicates that the chain has not been added to MetaMask
                if (err.code === 4902) {
                    console.log("please add ".concat(name).concat(" as a network"));
                        await window.ethereum.request({
                            method: 'wallet_addEthereumChain',
                            params: [
                                {
                                    chainName: chain,
                                    chainId: cid,
                                    nativeCurrency: { name: name, decimals: 18, symbol: symbol },
                                    rpcUrls: [rpc]
                                }
                            ]
                        });
                }
                else {
                    console.log(err);
                }
            }
        }
        await startApp(provider);
    } else {
        console.log("Please install MetaMask!")
    }



}
window.connectOrDisconnect = connectOrDisconnect;


async function startApp(provider) {
  if (provider !== window.ethereum) {
    console.error("Do you have multiple wallets installed?")
  }
  else {
    const accounts = await window.ethereum
    .request({ method: "eth_requestAccounts" })
    .catch((err) => {
      if (err.code === 4001) {
        console.log("Please connect to MetaMask.")
      } else {
        console.error(err)
      }
    })
    console.log("hi");
  const account = accounts[0];
  var web3 = new Web3(window.ethereum);
  const bal = await web3.eth.getBalance(account);
  //console.log("hi");
  console.log(bal);
  console.log(account);
  localStorage.setItem("acc",account.toString());
  document.getElementById("login-status").textContent = (account.toString().slice(0,8)).concat('..(Logout)');

  }
}


//0x6CeE2EbDA4512a6b5dAC74d3FCb0BBf4b9a7910C l30

//0xB67560d2D22BF5dCd5ee89a0e5d88aa9Acd5A878 desci

//0x3F8a211749020bfb29657be10db3EA19bBD67F86 mess
