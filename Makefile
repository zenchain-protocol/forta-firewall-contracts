.PHONY: deploy
deploy:
	forge script --rpc-url $(DEPLOY_RPC_URL) --broadcast ./script/Deployer.s.sol
