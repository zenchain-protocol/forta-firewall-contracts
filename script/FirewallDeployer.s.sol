// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Script, console} from "forge-std/Script.sol";
import {SecurityValidator} from "../src/SecurityValidator.sol";
import "../src/FirewallAccess.sol";
import "../src/ExternalFirewall.sol";
import {ProtectedContract as ExternalProtectedContract, Deployer as ExternalDeployer} from "../src/examples/ExternalFirewallIntegration.sol";
import {ProtectedContract as InternalProtectedContract, Deployer as InternalDeployer} from "../src/examples/InternalFirewallIntegration.sol";
import {ProtectedContract as ProxyProtectedContract, Deployer as ProxyDeployer} from "../src/examples/ProxyFirewallIntegration.sol";

contract DummyFirewallAccess {
    function isFirewallAdmin(address) public pure returns (bool) {
        return true;
    }

    function isProtocolAdmin(address) public pure returns (bool) {
        return true;
    }

    function isCheckpointManager(address) public pure returns (bool) {
        return true;
    }

    function isLogicUpgrader(address) public pure returns (bool) {
        return true;
    }

    function isCheckpointExecutor(address) public pure returns (bool) {
        return true;
    }

    function isTrustedAttester(address) public pure returns (bool) {
        return true;
    }
}

contract FirewallDeployerScript is Script {
    function run() public {
        string memory deployerPrivateKeyStr = vm.envString("DEPLOY_KEY");
        uint256 deployer = vm.parseUint(deployerPrivateKeyStr);
        vm.startBroadcast(deployer);

        SecurityValidator validator = new SecurityValidator(address(0));
        ExternalFirewall externalFirewall = new ExternalFirewall(
            ISecurityValidator(address(validator)),
            ICheckpointHook(address(0)),
            bytes32(0),
            IFirewallAccess(address(new DummyFirewallAccess()))
        );
        console.log("validator contract:", address(validator));
        console.log("external firewall contract:", address(externalFirewall));

        if (vm.envBool("DEPLOY_EXAMPLES")) {
            deployExternalFirewallIntegration(validator);
            deployInternalFirewallIntegration(validator);
            deployProxyFirewallIntegration(validator);
        }

        vm.stopBroadcast();
    }

    function deployExternalFirewallIntegration(SecurityValidator validator) internal {
        ExternalDeployer externalDeployer = new ExternalDeployer();
        ExternalProtectedContract externalProtected = externalDeployer.deploy(
            validator,
            address(this),
            address(this),
            bytes32(0)
        );
        console.log("Example ExternalProtectedContract deployed at:", address(externalProtected));
    }

    function deployInternalFirewallIntegration(SecurityValidator validator) internal {
        InternalDeployer internalDeployer = new InternalDeployer();
        InternalProtectedContract internalProtected = internalDeployer.deploy(
            validator,
            address(this),
            address(this),
            bytes32(0)
        );
        console.log("Example InternalProtectedContract deployed at:", address(internalProtected));
    }

    function deployProxyFirewallIntegration(SecurityValidator validator) internal {
        ProxyDeployer proxyDeployer = new ProxyDeployer();
        ProxyProtectedContract proxyProtected = proxyDeployer.deploy(
            validator,
            address(this),
            address(this),
            bytes32(0)
        );
        console.log("Example ProxyProtectedContract deployed at:", address(proxyProtected));
    }
}