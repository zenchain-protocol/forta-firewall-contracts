// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

uint256 constant ATTESTER_SLOT = 0;
uint256 constant ENTRY_HASH_SLOT = 1;
uint256 constant EXIT_HASH_SLOT = 2;
uint256 constant EXECUTION_HASH_SLOT = 3;

struct Attestation {
    address attester;
    uint256 timestamp;
    uint256 timeout;
    bool enter; // useful when exit call is scheduled independently
    bytes32 entryHash;
    bytes32 exitHash;
    address validator;
    bytes[] calls;
    address[] recipients;
}

interface ISecurityValidator {
    function hashAttestation(Attestation calldata attestation) external view returns (bytes32);
    function getAttester() external view returns (address);

    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) external;

    function tryEnterAttestedCall(bytes32 callHash) external returns (bool);

    function executeCheckpoint(bytes32 checkpointHash) external;
    function executeCheckpointUnsafe(bytes32 checkpointHash) external;

    function exitAttestedCall() external;

    function isExecuting() external view returns (bool);
    function isAttested() external view returns (bool);
}

contract SecurityValidator is EIP712 {
    error AttestationValidatorMismatch();
    error AttestationTimedOut();
    error AttesterMismatch();
    error EntryHashMismatch();
    error AttestationRequired();
    error ExitHashMismatch();
    error AttestationCallSizeMismatch();
    error AttestationCallFailed(uint256 index);

    bytes32 private constant _ATTESTATION_TYPEHASH = keccak256(
        "Attestation(address attester,uint256 timestamp,uint256 timeout,bool enter,bytes32 entryHash,bytes32 exitHash,address validator,bytes[] calls,address[] recipients)"
    );

    constructor() EIP712("SecurityValidator", "1") {}

    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) public {
        if (attestation.validator != address(this)) {
            revert AttestationValidatorMismatch();
        }
        if (block.timestamp > attestation.timestamp && block.timestamp - attestation.timestamp > attestation.timeout) {
            revert AttestationTimedOut();
        }
        if (attestation.calls.length != attestation.recipients.length) {
            revert AttestationCallSizeMismatch();
        }

        bytes32 structHash = hashAttestation(attestation);
        address attester = ECDSA.recover(structHash, attestationSignature);

        if (attester != attestation.attester) {
            revert AttesterMismatch();
        }

        assembly {
            tstore(ATTESTER_SLOT, attester)
        }

        bytes32 entryHash = attestation.entryHash;
        assembly {
            tstore(ENTRY_HASH_SLOT, entryHash)
        }
        if (attestation.enter) {
            assembly {
                tstore(EXECUTION_HASH_SLOT, entryHash)
            }
        }

        bytes32 exitHash = attestation.exitHash;
        assembly {
            tstore(EXIT_HASH_SLOT, exitHash)
        }

        for (uint256 i = 0; i < attestation.calls.length; i++) {
            (bool success,) = attestation.recipients[i].call(attestation.calls[i]);
            if (!success) revert AttestationCallFailed(i);
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
                    attestation.attester,
                    attestation.timestamp,
                    attestation.timeout,
                    attestation.entryHash,
                    attestation.exitHash,
                    attestation.validator,
                    keccak256(abi.encode(attestation.calls)),
                    keccak256(abi.encode(attestation.recipients))
                )
            )
        );
    }

    function tryEnterAttestedCall(bytes32 callHash) public returns (bool entered) {
        if (isExecuting() || !isAttested()) return false;

        bytes32 computed = keccak256(abi.encode(msg.sender, callHash));
        bytes32 entryHash;
        assembly {
            entryHash := tload(ENTRY_HASH_SLOT)
        }

        if (entryHash != computed) {
            revert EntryHashMismatch();
        }
        assembly {
            tstore(EXECUTION_HASH_SLOT, entryHash)
        }
        return true;
    }

    function isExecuting() public view returns (bool) {
        bytes32 executionHash;
        assembly {
            executionHash := tload(EXECUTION_HASH_SLOT)
        }
        return uint256(executionHash) > 0;
    }

    function isAttested() public view returns (bool) {
        bytes32 attester;
        assembly {
            attester := tload(ATTESTER_SLOT)
        }
        return uint256(attester) > 0;
    }

    function executeCheckpoint(bytes32 checkpointHash) public {
        if (!isAttested()) revert AttestationRequired();
        executeCheckpointUnsafe(checkpointHash);
    }

    function executeCheckpointUnsafe(bytes32 checkpointHash) public {
        bytes32 executionHash;
        assembly {
            executionHash := tload(EXECUTION_HASH_SLOT)
        }

        // Fall back to entry hash at the first checkpoint execution.
        if (uint256(executionHash) == 0) {
            assembly {
                executionHash := tload(ENTRY_HASH_SLOT)
            }
        }

        executionHash = executionHashFom(checkpointHash, msg.sender, executionHash);
        assembly {
            tstore(EXECUTION_HASH_SLOT, executionHash)
        }
    }

    function executionHashFom(bytes32 checkpointHash, address caller, bytes32 executionHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(checkpointHash, caller, executionHash));
    }

    function exitAttestedCall() public {
        bytes32 exitHash;
        bytes32 executionHash;
        assembly {
            exitHash := tload(EXIT_HASH_SLOT)
            executionHash := tload(EXECUTION_HASH_SLOT)
        }
        if (exitHash != executionHash) {
            revert ExitHashMismatch();
        }

        emptyTransientStorage();
    }

    function emptyTransientStorage() internal {
        assembly {
            tstore(ATTESTER_SLOT, 0)
            tstore(ENTRY_HASH_SLOT, 0)
            tstore(EXIT_HASH_SLOT, 0)
            tstore(EXECUTION_HASH_SLOT, 0)
        }
    }
}
