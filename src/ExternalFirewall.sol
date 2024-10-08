// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Firewall, ICheckpointHook} from "./Firewall.sol";
import {ISecurityValidator, Attestation} from "./SecurityValidator.sol";
import {IFirewallAccess} from "./FirewallAccess.sol";

interface IExternalFirewall {
    function executeCheckpoint(address caller, bytes4 selector, uint256 ref) external;
}

/**
 * @notice This contract provides firewall functionality externally. The integrator contract
 * should inherit the CheckpointExecutor contract and use the executeCheckpoint(bytes4,uint256)
 * function or the withCheckpoint(uint256) modifier to call this contract. The checkpoints must
 * be adjusted by calling the setCheckpoint(Checkpoint) function.
 */
contract ExternalFirewall is Firewall {
    constructor(
        ISecurityValidator _validator,
        ICheckpointHook _checkpointHook,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) {
        _updateFirewallConfig(_validator, _checkpointHook, _attesterControllerId, _firewallAccess);
    }

    /**
     * @notice Allows executing checkpoints externally from an integrator contract. The selector
     * is checked against the checkpoints configured on this contract.
     * @param selector Selector of the function which the checkpoint is configured and executed for
     * @param ref The reference number to compare with the threshold
     */
    function executeCheckpoint(address caller, bytes4 selector, uint256 ref) public onlyCheckpointExecutor {
        _secureExecution(caller, selector, ref);
    }
}
