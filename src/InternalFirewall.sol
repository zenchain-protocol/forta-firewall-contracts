// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {Firewall, ICheckpointHook} from "./Firewall.sol";
import {ISecurityValidator, Attestation} from "./SecurityValidator.sol";
import {IFirewallAccess} from "./FirewallAccess.sol";

/**
 * @notice This contract provides firewall functionality through inheritance. The child
 * contract must use the _secureExecution(uint256 ref) function to check checkpoint
 * activation conditions and execute checkpoints. The storage used by the Firewall contract
 * is namespaced and causes no collision. The checkpoints must be adjusted by calling the
 * setCheckpoint(Checkpoint) function.
 */
abstract contract InternalFirewall is Firewall, Multicall {
    constructor(
        ISecurityValidator _validator,
        ICheckpointHook _checkpointHook,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) {
        _updateFirewallConfig(_validator, _checkpointHook, _attesterControllerId, _firewallAccess);
    }
}
