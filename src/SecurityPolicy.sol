// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "./SecurityValidator.sol";

contract SecurityPolicy {
    SecurityValidator trustedValidator;

    constructor(SecurityValidator _trustedValidator) {
        trustedValidator = _trustedValidator;
    }

    function executeCheckpoint(bytes32 checkpointId, bytes32 checkpointHash, uint256 thresholdAmount) public {
        // TODO: Take into account the thresholds later.

        checkpointHash = policyCheckpointHashOf(checkpointId, checkpointHash, msg.sender);
        trustedValidator.executeCheckpoint(checkpointHash);
    }

    function policyCheckpointHashOf(bytes32 checkpointId, bytes32 checkpointHash, address caller)
        public
        pure
        returns (bytes32)
    {
        // Re-hashing here to make execution specific to every calling contract.
        // If a different contract uses the same checkpoint id and hash and calls this
        // policy contract, then the forwarded checkpoint hash is different due to the msg.sender.
        return keccak256(abi.encode(checkpointId, checkpointHash, caller));
    }
}
