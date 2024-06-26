.PHONY: deploy
deploy:
	forge script --rpc-url deploy --broadcast ./script/Deployer.s.sol

.PHONY: gas
gas:
	forge test --match-test attestationGas -vvvv

.PHONY: proxy-gas
proxy-gas:
	forge test --match-test testProxyGasChained --gas-report
	forge test --match-test testProxyGasDirect --gas-report
