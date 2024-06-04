// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "./SecurityValidator.sol";

contract SecurityPolicy {
    error UntrustedAttester();
    error CheckpointThresholdExceeded();

    mapping(bytes32 => uint256) thresholds;

    SecurityValidator trustedValidator;

    // TODO: This can alternatively point to an attester registry later.
    address trustedAttester;

    constructor(SecurityValidator _trustedValidator, address _trustedAttester) {
        trustedValidator = _trustedValidator;
        trustedAttester = _trustedAttester;
    }

    function executeCheckpoint(bytes32 checkpointId, uint256 referenceAmount) public {
        if (trustedValidator.getAttester() != trustedAttester) {
            revert UntrustedAttester();
        }

        uint256 threshold = thresholds[checkpointId];
        bytes32 checkpointHash = checkpointHashOf(checkpointId, msg.sender);
        uint256 acc;
        assembly {
            acc := tload(checkpointHash)
        }
        acc += referenceAmount;
        if (acc > threshold) {
            revert CheckpointThresholdExceeded();
        }
        assembly {
            tstore(checkpointHash, acc) // accumulate for the next time
        }

        trustedValidator.executeCheckpoint(checkpointHash);
    }

    function checkpointHashOf(bytes32 checkpointId, address caller) public pure returns (bytes32) {
        // Re-hashing here to make execution specific to every calling contract.
        // If a different contract uses the same checkpoint id and hash and calls this
        // policy contract, then the forwarded checkpoint hash is different due to the caller.
        return keccak256(abi.encode(checkpointId, caller));
    }
}
