// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

uint256 constant ATTESTER_SLOT = 0;
uint256 constant DEPTH_SLOT = 1;
uint256 constant HASH_SLOT = 2;
uint256 constant HASH_COUNT_SLOT = 3;
uint256 constant HASH_CACHE_INDEX_SLOT = 4;
uint256 constant HASH_CACHE_START_SLOT = 5;

address constant BYPASS_FLAG = 0x0000000000000000000000000000000000f01274; // "forta" in leetspeak

struct Attestation {
    uint256 timestamp;
    uint256 timeout;
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

contract SecurityValidator is EIP712 {
    error AttestationTimedOut();
    error AttestationRequired();
    error HashCountExceeded(uint256 atIndex);
    error InvalidExecutionHash(address validator, bytes32 expectedHash, bytes32 computedHash);

    event CheckpointExecuted(address validator, bytes32 executionHash);

    bytes32 private constant _ATTESTATION_TYPEHASH = keccak256(
        "Attestation(uint256 timestamp,uint256 timeout,bytes32[] executionHashes)"
    );

    constructor() EIP712("SecurityValidator", "1") {}

    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) public {
        if (block.timestamp > attestation.timestamp && block.timestamp - attestation.timestamp > attestation.timeout) {
            revert AttestationTimedOut();
        }

        bytes32 structHash = hashAttestation(attestation);
        address attester = ECDSA.recover(structHash, attestationSignature);

        // Initialize and empty transient storage.
        uint256 hashCount = attestation.executionHashes.length;
        assembly {
            tstore(ATTESTER_SLOT, attester)
            tstore(DEPTH_SLOT, 0)
            tstore(HASH_SLOT, 0)
            tstore(HASH_COUNT_SLOT, hashCount)
            tstore(HASH_CACHE_INDEX_SLOT, 0)
        }

        // Store all execution hashes.
        for (uint256 i = 0; i < attestation.executionHashes.length; i++) {
            bytes32 execHash = attestation.executionHashes[i];
            uint256 currIndex = HASH_CACHE_START_SLOT + i;
            assembly {
                tstore(currIndex, execHash)
            }
        }
    }

    function getCurrentAttester() public view returns (address) {
        address attester;
        assembly {
            attester := tload(ATTESTER_SLOT)
        }
        return attester;
    }

    function hashAttestation(Attestation calldata attestation) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    _ATTESTATION_TYPEHASH,
                    attestation.timestamp,
                    attestation.timeout,
                    keccak256(abi.encodePacked(attestation.executionHashes))
                )
            )
        );
    }

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

    function executeCheckpoint(bytes32 checkpointHash) public {
        bytes32 executionHash;
        assembly {
            executionHash := tload(HASH_SLOT)
        }

        // If there is no attestation and the bypass flag is not used,
        // then the transaction should revert.
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
        if (!bypassed && cacheIndex >= hashCount) {
            revert HashCountExceeded(cacheIndex);
        }

        bytes32 cachedHash;
        uint256 cachedHashSlot = cacheIndex + HASH_CACHE_START_SLOT;
        assembly {
            cachedHash := tload(cachedHashSlot)
        }
        if (!bypassed && executionHash != cachedHash) {
            revert InvalidExecutionHash(address(this), cachedHash, executionHash);
        }
        cacheIndex++;

        assembly {
            tstore(HASH_SLOT, executionHash)
            tstore(HASH_CACHE_INDEX_SLOT, cacheIndex)
        }
    }

    function executionHashFrom(bytes32 checkpointHash, address caller, bytes32 executionHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(checkpointHash, caller, executionHash));
    }
}
