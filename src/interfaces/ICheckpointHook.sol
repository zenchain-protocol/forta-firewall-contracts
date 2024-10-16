// SPDX-License-Identifier: UNLICENSED
// See Forta Network License: https://github.com/forta-network/forta-firewall-contracts/blob/master/LICENSE.md

pragma solidity ^0.8.25;

enum HookResult {
    Inconclusive,
    ForceActivation,
    ForceDeactivation
}

/// @notice An interface to support custom configurations per executed checkpoint.
interface ICheckpointHook {
    function handleCheckpoint(address caller, bytes4 selector, uint256 ref) external view returns (HookResult);
}
