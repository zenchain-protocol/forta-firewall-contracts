.PHONY: dry-run-deploy
dry-run-deploy:
	forge script \
		./script/FirewallDeployer.s.sol:FirewallDeployerScript \
		--sig "run()" \
		--chain-id 8408 \
		--fork-url zenchain_testnet

.PHONY: deploy
deploy:
	forge script \
		--rpc-url zenchain_testnet \
		--chain-id 8408 \
		--broadcast \
		./script/Deployer.s.sol

.PHONY: deploy-firewall
deploy-firewall:
	forge script \
		./script/FirewallDeployer.s.sol:FirewallDeployerScript \
		--rpc-url zenchain_testnet \
		--chain-id 8408 \
		--broadcast \
		--slow \
		--verify

.PHONY: gas
gas:
	forge test --match-test attestationGas -vvvv

.PHONY: proxy-gas
proxy-gas:
	forge test --match-test testProxyGasChained --gas-report
	forge test --match-test testProxyGasDirect --gas-report
