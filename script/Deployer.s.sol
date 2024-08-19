// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import "../src/SecurityValidator.sol";
import "../src/SecurityPolicy.sol";
import "../test/helpers/DummyVault.sol";
import {EthereumVaultConnector} from "evc/EthereumVaultConnector.sol";

contract DeployerScript is Script {
    function run() public {
        string memory deployerPrivateKeyStr = vm.envString("DEPLOY_KEY");
        uint256 deployer = vm.parseUint(deployerPrivateKeyStr);
        vm.startBroadcast(deployer);

        // 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 - dev attester
        uint256 attesterPrivateKey = vm.parseUint("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        address attester = vm.addr(attesterPrivateKey);

        SecurityValidator validator = new SecurityValidator();
        EthereumVaultConnector evc = new EthereumVaultConnector();
        DummyVault vault = new DummyVault(ISecurityValidator(address(validator)));
        console.log("validator contract:", address(validator));
        console.log("evc contract:", address(evc));
        console.log("vault contract:", address(vault));

        vm.stopBroadcast();
    }
}
