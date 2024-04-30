.PHONY: deploy
deploy:
	forge script --rpc-url deploy --broadcast ./script/Deployer.s.sol
