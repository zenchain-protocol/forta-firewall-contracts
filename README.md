## Forta Firewall Contracts

This repository contains the firewall contract library useful for integrating with Forta Attestations.

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

or

```sh
make deploy-firewall
```

## Quick Forge reference

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```
