const axios = require('axios');
require('dotenv/config');
const { ethers } = require('ethers');

const attesterUrl = process.env.ATTESTER_URL;
const jsonRpcUrl = process.env.RPC;
const provider = new ethers.JsonRpcProvider(jsonRpcUrl);
const signer = new ethers.Wallet(process.env.USER_KEY, provider);
const userAddr = signer.address;

const evcAbi = [
  {
    "inputs": [
      {
        "internalType": "struct IEVC.BatchItem[]",
        "name": "items",
        "type": "tuple[]",
        "components": [
          {
            "internalType": "address",
            "name": "targetContract",
            "type": "address"
          },
          {
            "internalType": "address",
            "name": "onBehalfOfAccount",
            "type": "address"
          },
          {
            "internalType": "uint256",
            "name": "value",
            "type": "uint256"
          },
          {
            "internalType": "bytes",
            "name": "data",
            "type": "bytes"
          }
        ]
      }
    ],
    "stateMutability": "payable",
    "type": "function",
    "name": "batch"
  }
]

const validatorAbi = [
  {
    "type": "function",
    "name": "hashAttestation",
    "inputs": [
      {
        "name": "attestation",
        "type": "tuple",
        "internalType": "struct Attestation",
        "components": [
          {
            "name": "timestamp",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "timeout",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "executionHashes",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          }
        ]
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "saveAttestation",
    "inputs": [
      {
        "name": "attestation",
        "type": "tuple",
        "internalType": "struct Attestation",
        "components": [
          {
            "name": "timestamp",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "timeout",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "executionHashes",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          }
        ]
      },
      {
        "name": "attestationSignature",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  }
]

const vaultAbi = [
  {
    "type": "function",
    "name": "doFirst",
    "inputs": [
      {
        "name": "amount",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "doSecond",
    "inputs": [
      {
        "name": "amount",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  }
]

const evcAddr = process.env.EVC_CONTRACT;
const vaultAddr = process.env.VAULT_CONTRACT;

const evcContract = new ethers.Contract(evcAddr, evcAbi);
const vaultContract = new ethers.Contract(vaultAddr, vaultAbi);

const originalBatch = [
  Object.values({
    targetContract: vaultAddr,
    onBehalfOfAccount: userAddr,
    value: 0,
    data: vaultContract.interface.encodeFunctionData("doFirst", [123])
  }),
  Object.values({
    targetContract: vaultAddr,
    onBehalfOfAccount: userAddr,
    value: 0,
    data: vaultContract.interface.encodeFunctionData("doSecond", [456])
  })
];
const originalCall = evcContract.interface.encodeFunctionData("batch", [originalBatch]);


// TODO: Try doing an eth_call with the original call to see if it really reverts and
// with what error. The error message will be helpful in determining whether
// an attestation needs to be requested or not.

async function main() {
  const result = await axios.post(attesterUrl,
    {
      from: userAddr,
      to: evcAddr,
      input: originalCall,
      
      // Integration testing params:
      jsonRpcUrl,
    }
  );

  console.log(`got attestation result:`);
  console.log(result.data);

  const validatorContract = new ethers.Contract(result.data.validator, validatorAbi, signer);

  // Prepend attestation to the original batch.
  const { attestation, signature } = result.data;
  const finalBatch = [
    Object.values({
      targetContract: result.data.validator,
      onBehalfOfAccount: userAddr,
      value: 0,
      data: validatorContract.interface.encodeFunctionData("saveAttestation", [
        Object.values(attestation),
        signature
      ])
    }),
  ].concat(originalBatch);

  const finalCall = evcContract.interface.encodeFunctionData("batch", [finalBatch]);

  const txResult = await signer.sendTransaction({
    to: evcAddr,
    data: finalCall,
    gasLimit: 200000
  });
  console.log(`transaction sent with attestation: ${txResult.hash}`);
}

main();
