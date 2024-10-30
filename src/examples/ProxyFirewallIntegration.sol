// SPDX-License-Identifier: GNU General Public License Version 3
// See license at: https://github.com/forta-network/forta-firewall-contracts/blob/master/LICENSE-GPLv3.md
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ProxyFirewall} from "../ProxyFirewall.sol";
import {ISecurityValidator} from "../interfaces/ISecurityValidator.sol";
import {FirewallAccess} from "../FirewallAccess.sol";
import {IProxyFirewall} from "../interfaces/IProxyFirewall.sol";
import {Checkpoint} from "../interfaces/Checkpoint.sol";
import {Activation} from "../interfaces/Activation.sol";
import {
    FIREWALL_ADMIN_ROLE,
    PROTOCOL_ADMIN_ROLE,
    ATTESTER_MANAGER_ROLE,
    TRUSTED_ATTESTER_ROLE
} from "../FirewallAccess.sol";

/// @notice You don't even need to modify your logic contract. See how neat that is?
contract ProtectedContract {
    function foo(uint256 num) public {}
}

/// @notice This deployer is not intended for production use and only demonstrates the steps
/// for firewall integration.
contract Deployer {
    event DeployedFirewall(ProxyFirewall firewall);
    event DeployedProtectedContract(ProtectedContract protectedContract);
    event DeployedProxy(ERC1967Proxy proxy);

    function deploy(
        ISecurityValidator validator,
        address firewallAdmin,
        address trustedAttester,
        bytes32 attesterControllerId
    ) public returns (ProtectedContract) {
        /// no args - first logic contract
        ProxyFirewall firewall = new ProxyFirewall();
        emit DeployedFirewall(firewall);

        /// second logic contract
        ProtectedContract protectedContract = new ProtectedContract();
        emit DeployedProtectedContract(protectedContract);

        /// will renounce default role later below
        FirewallAccess firewallAccess = new FirewallAccess(address(this));

        /// will renounce later below
        firewallAccess.grantRole(FIREWALL_ADMIN_ROLE, address(this));
        firewallAccess.grantRole(PROTOCOL_ADMIN_ROLE, address(this));
        firewallAccess.grantRole(ATTESTER_MANAGER_ROLE, address(this));

        /// set the trusted attester:
        /// this will be necessary when "foo()" receives an attested call later.
        firewallAccess.grantRole(TRUSTED_ATTESTER_ROLE, trustedAttester);

        bytes memory data = abi.encodeWithSelector(
            ProxyFirewall.initializeFirewallConfig.selector,
            address(validator),
            address(0), // checkpoint hook - optional
            attesterControllerId,
            address(firewallAccess)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(firewall), data);
        emit DeployedProxy(proxy);

        data = new bytes(0);
        IProxyFirewall(address(proxy)).upgradeNextAndCall(address(protectedContract), data);

        /// setting a checkpoint
        Checkpoint memory checkpoint = Checkpoint({
            threshold: 0,
            refStart: 4,
            refEnd: 36,
            activation: Activation.AlwaysActive,
            trustedOrigin: false
        });
        IProxyFirewall(address(proxy)).setCheckpoint(ProtectedContract.foo.selector, checkpoint);

        /// granting the default role
        firewallAccess.grantRole(0x00, firewallAdmin);
        /// renounce all roles of this contract
        firewallAccess.renounceRole(0x00, address(this));
        firewallAccess.renounceRole(FIREWALL_ADMIN_ROLE, address(this));
        firewallAccess.renounceRole(PROTOCOL_ADMIN_ROLE, address(this));
        firewallAccess.renounceRole(ATTESTER_MANAGER_ROLE, address(this));

        return ProtectedContract(address(proxy));
    }
}
