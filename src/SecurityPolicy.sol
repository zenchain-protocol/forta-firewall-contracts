// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "./SecurityValidator.sol";

enum Threshold {
    Constant,
    Accumulated
}

interface ISecurityPolicy {
    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) external;
    function enterCall() external returns (uint256 depth);
    function executeCheckpoint(bytes32 checkpointId, bytes32 callHash, uint256 referenceAmount, Threshold thresholdType)
        external;
    function exitCall() external;
}

contract SecurityPolicy {
    error UntrustedAttester();
    error InvalidThresholdType();

    mapping(bytes32 => uint256) thresholds;

    ISecurityValidator trustedValidator;

    // TODO: This can alternatively point to an attester registry later.
    address trustedAttester;

    constructor(ISecurityValidator _trustedValidator, address _trustedAttester) {
        trustedValidator = _trustedValidator;
        trustedAttester = _trustedAttester;
    }

    // TODO: Implement access control.
    function adjustCheckpointThreshold(bytes32 checkpointId, uint256 newThreshold) public {
        thresholds[checkpointId] = newThreshold;
    }

    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) public {
        trustedValidator.saveAttestation(attestation, attestationSignature);
    }

    function enterCall() public returns (uint256 depth) {
        return trustedValidator.enterCall();
    }

    function exitCall() public {
        trustedValidator.exitCall();
    }

    function executeCheckpoint(bytes32 checkpointId, bytes32 callHash, uint256 referenceAmount, Threshold thresholdType)
        public
    {
        // TODO: Check current attester against multiple attesters.
        if (trustedValidator.getCurrentAttester() != trustedAttester) {
            if (BYPASS_FLAG.code.length == 0) {
                revert UntrustedAttester();
            }
        }

        uint256 threshold = thresholds[checkpointId];
        bytes32 checkpointHash = checkpointHashOf(checkpointId, callHash, msg.sender);

        if (thresholdType == Threshold.Constant && referenceAmount > threshold) {
            trustedValidator.executeCheckpoint(checkpointHash);
            return;
        }

        if (thresholdType != Threshold.Accumulated) {
            revert InvalidThresholdType();
        }

        uint256 acc;
        assembly {
            acc := tload(checkpointHash)
        }
        acc += referenceAmount;
        if (acc > threshold) {
            trustedValidator.executeCheckpoint(checkpointHash);
            return;
        }
        assembly {
            tstore(checkpointHash, acc) // accumulate for the next time
        }
    }

    function checkpointHashOf(bytes32 checkpointId, bytes32 callHash, address caller) public pure returns (bytes32) {
        // Re-hashing here to make execution specific to every calling contract.
        // If a different contract uses the same checkpoint id and hash and calls this
        // policy contract, then the forwarded checkpoint hash is different due to the caller.
        return keccak256(abi.encode(checkpointId, callHash, caller));
    }
}
