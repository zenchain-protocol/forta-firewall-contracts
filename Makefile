.PHONY: deploy
deploy:
	forge script --rpc-url deploy --broadcast ./script/Deployer.s.sol

.PHONY: gas
gas:
	forge test --match-test attestationGas -vvvv
