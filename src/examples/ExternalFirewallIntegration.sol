// SPDX-License-Identifier: GNU General Public License Version 3
// See license at: https://github.com/forta-network/forta-firewall-contracts/blob/master/LICENSE-GPLv3.md
pragma solidity ^0.8.25;

import {CheckpointExecutor} from "../CheckpointExecutor.sol";
import {ExternalFirewall} from "../ExternalFirewall.sol";
import {ISecurityValidator} from "../interfaces/ISecurityValidator.sol";
import {FirewallAccess} from "../FirewallAccess.sol";
import {FirewallRouter} from "../FirewallRouter.sol";
import {IExternalFirewall} from "../interfaces/IExternalFirewall.sol";
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

contract ProtectedContract is CheckpointExecutor {
    constructor(IExternalFirewall externalFirewall) {
        _setExternalFirewall(externalFirewall);
    }

    modifier safeExecution() {
        _executeCheckpoint(msg.sig, keccak256(msg.data));
        _;
    }

    function foo(uint256 num) public safeExecution {}
}

/// @notice This deployer is not intended for production use and only demonstrates the steps
/// for firewall integration.
contract Deployer {
    event DeployedFirewall(ExternalFirewall firewall);
    event DeployedFirewallRouter(FirewallRouter firewallRouter);
    event DeployedProtectedContract(ProtectedContract protectedContract);

    function deploy(
        ISecurityValidator validator,
        address firewallAdmin,
        address trustedAttester,
        bytes32 attesterControllerId
    ) public returns (ProtectedContract) {
        /// will renounce default role later below
        FirewallAccess firewallAccess = new FirewallAccess(address(this));

        ExternalFirewall externalFirewall =
            new ExternalFirewall(validator, ICheckpointHook(address(0)), attesterControllerId, firewallAccess);
        emit DeployedFirewall(externalFirewall);

        /// deploy a router for firewall upgradeability
        FirewallRouter firewallRouter = new FirewallRouter(externalFirewall, firewallAccess);
        emit DeployedFirewallRouter(firewallRouter);

        ProtectedContract protectedContract = new ProtectedContract(firewallRouter);
        emit DeployedProtectedContract(protectedContract);

        /// will renounce later below
        firewallAccess.grantRole(FIREWALL_ADMIN_ROLE, address(this));
        firewallAccess.grantRole(PROTOCOL_ADMIN_ROLE, address(this));
        firewallAccess.grantRole(ATTESTER_MANAGER_ROLE, address(this));

        /// let protected contract execute checkpoints on the external firewall
        firewallAccess.grantRole(CHECKPOINT_EXECUTOR_ROLE, address(protectedContract));
        firewallAccess.grantRole(CHECKPOINT_EXECUTOR_ROLE, address(firewallRouter));

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
        externalFirewall.setCheckpoint(ProtectedContract.foo.selector, checkpoint);

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
