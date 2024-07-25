// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

address constant BYPASS_FLAG = 0x0000000000000000000000000000000000f01274; // "forta" in leetspeak

/// @notice Set of values that enable execution of call(s)
struct Attestation {
    /// @notice Deadline UNIX timestamp
    uint256 deadline;
    /**
     * @notice Ordered hashes which should be produced at every checkpoint execution
     * in this contract. An attester uses these hashes to enable a specific execution
     * path.
     */
    bytes32[] executionHashes;
}

interface ISecurityValidator {
    function hashAttestation(Attestation calldata attestation) external view returns (bytes32);
    function getCurrentAttester() external view returns (address);

    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) external;

    function enterCall() external returns (uint256 depth);
    function executeCheckpoint(bytes32 checkpointHash) external;
    function exitCall() external;
}

/**
 * @title Validator contract used for attestations
 * @notice A singleton to be used by attesters to enable execution and contracts to ensure
 * that execution was enabled by an attester.
 */
contract SecurityValidator is EIP712 {
    error AttestationDeadlineExceeded();
    error AttestationRequired();
    error HashCountExceeded(uint256 atIndex);
    error InvalidExecutionHash(address validator, bytes32 expectedHash, bytes32 computedHash);
    error InvalidAttestation();

    event CheckpointExecuted(address validator, bytes32 executionHash);

    /**
     * @notice Transient storage slots used for storing the attestation values
     * and executing checkpoints
     */
    uint256 constant ATTESTER_SLOT = 0;
    uint256 constant DEPTH_SLOT = 1;
    uint256 constant HASH_SLOT = 2;
    uint256 constant HASH_COUNT_SLOT = 3;
    uint256 constant HASH_CACHE_INDEX_SLOT = 4;
    uint256 constant HASH_CACHE_START_SLOT = 5;

    /// @notice Used for EIP-712 message hash calculation
    bytes32 private constant _ATTESTATION_TYPEHASH =
        keccak256("Attestation(uint256 deadline,bytes32[] executionHashes)");

    constructor() EIP712("SecurityValidator", "1") {}

    /**
     * @notice Accepts and stores an attestation to the transient storage introduced
     * with EIP-1153. Multiple contracts that operate in the same transaction can call
     * a singleton of this contract. The stored values are later used during checkpoint
     * execution.
     * @param attestation The set of fields that correspond to and enable the execution of call(s)
     * @param attestationSignature Signature of EIP-712 message
     */
    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) public {
        if (block.timestamp > attestation.deadline) {
            revert AttestationDeadlineExceeded();
        }

        // Avoid reentrancy: Make sure that we are starting from a zero state or after
        // a previous attestation has beenUsed.
        _idleOrDone();

        bytes32 structHash = hashAttestation(attestation);
        address attester = ECDSA.recover(structHash, attestationSignature);

        /// Initialize and empty transient storage.
        uint256 hashCount = attestation.executionHashes.length;
        assembly {
            tstore(ATTESTER_SLOT, attester)
            tstore(DEPTH_SLOT, 0)
            tstore(HASH_SLOT, 0)
            tstore(HASH_COUNT_SLOT, hashCount)
            tstore(HASH_CACHE_INDEX_SLOT, 0)
        }

        /// Store all execution hashes.
        for (uint256 i = 0; i < attestation.executionHashes.length; i++) {
            bytes32 execHash = attestation.executionHashes[i];
            uint256 currIndex = HASH_CACHE_START_SLOT + i;
            assembly {
                tstore(currIndex, execHash)
            }
        }
    }

    /// @notice Returns the attester address which attested to the current execution
    function getCurrentAttester() public view returns (address) {
        address attester;
        assembly {
            attester := tload(ATTESTER_SLOT)
        }
        return attester;
    }

    /**
     * @notice Produces the EIP-712 hash of the attestation message.
     * @param attestation The set of fields that correspond to and enable the execution of call(s)
     */
    function hashAttestation(Attestation calldata attestation) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    _ATTESTATION_TYPEHASH,
                    attestation.deadline,
                    keccak256(abi.encodePacked(attestation.executionHashes))
                )
            )
        );
    }

    /// @notice Assists in keeping track of the depth of the calls during checkpoint execution
    function enterCall() public returns (uint256 depth) {
        assembly {
            depth := tload(DEPTH_SLOT)
        }
        depth++;
        assembly {
            tstore(DEPTH_SLOT, depth)
        }
        return depth;
    }

    /// @notice Assists in keeping track of the depth of the calls during checkpoint execution
    function exitCall() public {
        uint256 depth;
        assembly {
            depth := tload(DEPTH_SLOT)
        }
        depth--;
        assembly {
            tstore(DEPTH_SLOT, depth)
        }
    }

    /**
     * @notice Computes an execution hash by using given arbitrary checkpoint hash, msg.sender
     * and the previous execution hash. Requires the computed execution hash to be equal to
     * the currently pointed execution hash from the attestation.
     *
     * @param checkpointHash An arbitrary hash which can be computed by using variety of values
     * that occur during a call
     */
    function executeCheckpoint(bytes32 checkpointHash) public {
        bytes32 executionHash;
        assembly {
            executionHash := tload(HASH_SLOT)
        }

        /// If there is no attestation and the bypass flag is not used,
        /// then the transaction should revert.
        bool bypassed;
        if (uint160(getCurrentAttester()) == 0) {
            if (BYPASS_FLAG.code.length == 0) {
                revert AttestationRequired();
            } else {
                bypassed = true;
            }
        }

        executionHash = executionHashFrom(checkpointHash, msg.sender, executionHash);
        emit CheckpointExecuted(address(this), executionHash);

        uint256 cacheIndex;
        uint256 hashCount;
        assembly {
            cacheIndex := tload(HASH_CACHE_INDEX_SLOT)
            hashCount := tload(HASH_COUNT_SLOT)
        }
        /// Current execution should not try to execute more checkpoints than attested to.
        if (!bypassed && cacheIndex >= hashCount) {
            revert HashCountExceeded(cacheIndex);
        }

        bytes32 cachedHash;
        uint256 cachedHashSlot = cacheIndex + HASH_CACHE_START_SLOT;
        assembly {
            cachedHash := tload(cachedHashSlot)
        }
        /// Computed hash should match with the hash that was attested to.
        if (!bypassed && executionHash != cachedHash) {
            revert InvalidExecutionHash(address(this), cachedHash, executionHash);
        }

        /// Point to the next hash from the attestation and store the latest computed
        /// hash along with the new index.
        cacheIndex++;
        assembly {
            tstore(HASH_SLOT, executionHash)
            tstore(HASH_CACHE_INDEX_SLOT, cacheIndex)
        }
    }

    /**
     * @notice Makes sure that the attestation matches with current transaction
     * and all checkpoints were used correctly.
     */
    function validateFinalState() public view {
        _idleOrDone();
    }

    function _idleOrDone() internal view {
        uint256 cacheIndex;
        uint256 hashCount;
        assembly {
            cacheIndex := tload(HASH_CACHE_INDEX_SLOT)
            hashCount := tload(HASH_COUNT_SLOT)
        }
        if (cacheIndex < hashCount) {
            revert InvalidAttestation();
        }
    }

    /**
     * @notice Computes the execution hash from given inputs.
     * @param checkpointHash An arbitrary hash which can be computed by using variety of values
     * that occur during a call
     * @param caller msg.sender of executeCheckpoint() call
     * @param executionHash Previous execution hash
     */
    function executionHashFrom(bytes32 checkpointHash, address caller, bytes32 executionHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(checkpointHash, caller, executionHash));
    }
}
