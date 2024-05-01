## Forta Attestation Contracts

## Deployment

Create an `.env` file like

```
DEPLOY_RPC=https://polygon-mainnet.g.alchemy.com/v2/...
DEPLOY_KEY=1a735a19b4a253527031d0c47a3478e13eda92e717f3a5866a56b3864dc29e7b
```

then do

```sh
make deploy
```

## How to use the contract addresses

You can see the addresses in the script logs like:
```
== Logs ==
  validator contract: 0x629DEA308296c5b8e65a376cD0181658CAA2Ed4A
  policy contract: 0xa6FF2BEefB48b0489f4e587D529F9ce6439AFEfe
```

The validator contract address and the deployed chain RPC needs to be provided to the attester in the same request which the user tx/op is sent for screening.

The policy contract is the one which takes the checkpoint execution requests. The protocol contract that defines checkpoint hashes must make calls to the policy contract to execute them.

## Quick Forge reference

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```
