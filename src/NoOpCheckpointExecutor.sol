// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

// This is used as the SecurityValidator contract during user transaction simulation
// so that the attestation requirement can be disabled and all checkpoint hashes are visible.
contract NoOpCheckpointExecutor {
    function executeCheckpoint(bytes32 checkpointHash) public {}
}
