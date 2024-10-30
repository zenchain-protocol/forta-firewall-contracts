// SPDX-License-Identifier: GNU General Public License Version 3
// See license at: https://github.com/forta-network/forta-firewall-contracts/blob/master/LICENSE-GPLv3.md
pragma solidity ^0.8.25;

import {InternalFirewall} from "../InternalFirewall.sol";
import {ISecurityValidator} from "../interfaces/ISecurityValidator.sol";
import {FirewallAccess} from "../FirewallAccess.sol";
import {IFirewallAccess} from "../interfaces/IFirewallAccess.sol";
import {ICheckpointHook} from "../interfaces/ICheckpointHook.sol";
import {
    FIREWALL_ADMIN_ROLE,
    PROTOCOL_ADMIN_ROLE,
    CHECKPOINT_EXECUTOR_ROLE,
    ATTESTER_MANAGER_ROLE,
    TRUSTED_ATTESTER_ROLE
} from "../FirewallAccess.sol";
import {Checkpoint} from "../interfaces/Checkpoint.sol";
import {Activation} from "../interfaces/Activation.sol";

contract ProtectedContract is InternalFirewall {
    constructor(
        ISecurityValidator _validator,
        ICheckpointHook _checkpointHook,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) InternalFirewall(_validator, _checkpointHook, _attesterControllerId, _firewallAccess) {}

    function foo(uint256 num) public safeExecution {}
}

/// @notice This deployer is not intended for production use and only demonstrates the steps
/// for firewall integration.
contract Deployer {
    event DeployedProtectedContract(ProtectedContract protectedContract);

    function deploy(
        ISecurityValidator validator,
        address firewallAdmin,
        address trustedAttester,
        bytes32 attesterControllerId
    ) public returns (ProtectedContract) {
        /// will renounce default role later below
        FirewallAccess firewallAccess = new FirewallAccess(address(this));

        ProtectedContract protectedContract =
            new ProtectedContract(validator, ICheckpointHook(address(0)), attesterControllerId, firewallAccess);
        emit DeployedProtectedContract(protectedContract);

        /// will renounce later below
        firewallAccess.grantRole(FIREWALL_ADMIN_ROLE, address(this));
        firewallAccess.grantRole(PROTOCOL_ADMIN_ROLE, address(this));
        firewallAccess.grantRole(ATTESTER_MANAGER_ROLE, address(this));

        /// set the trusted attester:
        /// this will be necessary when "foo()" receives an attested call later.
        firewallAccess.grantRole(TRUSTED_ATTESTER_ROLE, trustedAttester);

        /// setting a checkpoint
        Checkpoint memory checkpoint = Checkpoint({
            threshold: 0,
            refStart: 4,
            refEnd: 36,
            activation: Activation.AlwaysActive,
            trustedOrigin: false
        });
        protectedContract.setCheckpoint(ProtectedContract.foo.selector, checkpoint);

        /// granting the default role
        firewallAccess.grantRole(0x00, firewallAdmin);
        /// renounce all roles of this contract
        firewallAccess.renounceRole(0x00, address(this));
        firewallAccess.renounceRole(FIREWALL_ADMIN_ROLE, address(this));
        firewallAccess.renounceRole(PROTOCOL_ADMIN_ROLE, address(this));
        firewallAccess.renounceRole(ATTESTER_MANAGER_ROLE, address(this));

        return protectedContract;
    }
}
