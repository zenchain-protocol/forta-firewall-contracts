// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import "./SecurityValidator.sol";

enum Threshold {
    Constant,
    Accumulated
}

interface ISecurityPolicy {
    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) external;
    function executeCheckpoint(bytes32 checkpointId, bytes32 callHash, uint256 referenceAmount, Threshold thresholdType)
        external;
}

/**
 * @title Security policy definition contract
 * @notice Validates that the signer of the current attestation is a trusted one and provides
 * threshold functionality for checkpoint execution. One or many contracts that belong to the
 * same deployer or DAO can point to one or many security policy contracts. The same authority
 * which administrates a contract can adjust in this contract the thresholds for each checkpoint
 * to be executed by the logic contract code.
 */
contract SecurityPolicy {
    using StorageSlot for bytes32;

    error UntrustedAttester();
    error InvalidThresholdType();

    mapping(bytes32 => uint256) thresholds;

    ISecurityValidator trustedValidator;

    /// TODO: This can alternatively point to an attester registry later.
    address trustedAttester;

    constructor(ISecurityValidator _trustedValidator, address _trustedAttester) {
        trustedValidator = _trustedValidator;
        trustedAttester = _trustedAttester;
    }

    modifier withTrustedAttester() {
        _;
        /// TODO: Check current attester against multiple attesters.
        if (trustedValidator.getCurrentAttester() != trustedAttester) {
            if (BYPASS_FLAG.code.length == 0) {
                revert UntrustedAttester();
            }
        }
    }

    /**
     * @notice Adjusts the threshold value of a checkpoint
     * @dev TODO: Need to implement access control.
     * @param checkpointId Identifier of the checkpoint, defined by the calling contract
     * @param newThreshold The value which given reference should be compared against
     */
    function adjustCheckpointThreshold(bytes32 checkpointId, uint256 newThreshold) public {
        thresholds[checkpointId] = newThreshold;
    }

    /// @notice Proxies the call to the validator contract
    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) public {
        trustedValidator.saveAttestation(attestation, attestationSignature);
    }

    /**
     * @notice Gates the checkpoint execution call to the validator contract
     * @param checkpointId Identifier of the executed checkpoint.
     * @param callHash The hash of the call provided by the calling contract. It is up to the
     * calling contract to make it specific to the received call or more general.
     * @param referenceAmount The reference amount to compare the threshold against. The usage
     * depends on the threshold type.
     * @param thresholdType If accumulated, then given values accumulate over time and get compared
     * to the threshold. Otherwise, the threshold is always compared directly with the reference.
     * The accumulated threshold is useful in cases which a below-threshold repeated action can
     * take place multiple times in the same transaction.
     */
    function executeCheckpoint(bytes32 checkpointId, bytes32 callHash, uint256 referenceAmount, Threshold thresholdType)
        public
        withTrustedAttester
    {
        uint256 threshold = thresholds[checkpointId];
        bytes32 checkpointHash = checkpointHashOf(checkpointId, callHash, msg.sender);

        if (thresholdType == Threshold.Constant && referenceAmount > threshold) {
            trustedValidator.executeCheckpoint(checkpointHash);
            return;
        }

        if (thresholdType != Threshold.Accumulated) {
            revert InvalidThresholdType();
        }

        bytes32 slot = keccak256(abi.encode(checkpointId, msg.sender));
        uint256 acc = StorageSlot.tload(slot.asUint256());
        acc += referenceAmount;
        if (acc > threshold) {
            trustedValidator.executeCheckpoint(checkpointHash);
            return;
        }
        StorageSlot.tstore(slot.asUint256(), acc);
    }

    /**
     * @notice Computes the checkpoint hash with given values.
     * @param checkpointId Identifier of the executed checkpoint.
     * @param callHash The hash of the call provided by the calling contract. It is up to the
     * calling contract to make it specific to the received call or more general.
     * @param caller msg.sender of the executeCheckpoint() call.
     */
    function checkpointHashOf(bytes32 checkpointId, bytes32 callHash, address caller) public pure returns (bytes32) {
        /// Re-hashing here to make execution specific to every calling contract.
        /// If a different contract uses the same checkpoint id and hash and calls this
        /// policy contract, then the forwarded checkpoint hash becomes different due to the caller.
        /// This disables checkpoint reuse or collision between different contracts.
        return keccak256(abi.encode(checkpointId, callHash, caller));
    }
}
