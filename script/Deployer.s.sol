// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import "../src/SecurityValidator.sol";
import "../src/SecurityPolicy.sol";

// contract DeployerScript is Script {
//     function run() public {
//         string memory deployerPrivateKeyStr = vm.envString("DEPLOY_KEY");
//         uint256 deployer = vm.parseUint(deployerPrivateKeyStr);
//         vm.startBroadcast(deployer);

//         // 0x25f683D08bb45ce0cB4e587d2F1DA23D9aD01FDb - dev attester
//         uint256 attesterPrivateKey = vm.parseUint("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
//         address attester = vm.addr(attesterPrivateKey);

//         SecurityValidator validator = new SecurityValidator(attester, true);
//         SecurityPolicy policy = new SecurityPolicy(validator);
//         console.log("validator contract:", address(validator));
//         console.log("policy contract:", address(policy));

//         vm.stopBroadcast();
//     }
// }
