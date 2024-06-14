// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

uint256 constant ATTESTER_SLOT = 0;
uint256 constant FINAL_HASH_SLOT = 1;
uint256 constant EXECUTION_HASH_SLOT = 2;
uint256 constant DEPTH_SLOT = 3;

address constant BYPASS_FLAG = 0x0000000000000000000000000000000000f01274; // "forta" in leetspeak

struct Attestation {
    address attester;
    uint256 timestamp;
    uint256 timeout;
    bytes32 finalHash;
    address validator;
    bytes[] calls;
    address[] recipients;
}

interface ISecurityValidator {
    function hashAttestation(Attestation calldata attestation) external view returns (bytes32);
    function getCurrentAttester() external view returns (address);

    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) external;
    function validateExecution() external;

    function enterCall() external returns (uint256 depth);
    function executeCheckpoint(bytes32 checkpointHash) external;
    function exitCall() external;
}

contract SecurityValidator is EIP712 {
    error AttestationValidatorMismatch();
    error AttestationTimedOut();
    error AttesterMismatch();
    error AttestationRequired();
    error ValidationFailed(address validator, bytes32 computedHash);
    error AttestationCallSizeMismatch();
    error AttestationCallFailed(uint256 index);

    event CheckpointExecuted(address validator, bytes32 executionHash);

    bytes32 private constant _ATTESTATION_TYPEHASH = keccak256(
        "Attestation(address attester,uint256 timestamp,uint256 timeout,bytes32 finalHash,address validator,bytes[] calls,address[] recipients)"
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

        bytes32 finalHash = attestation.finalHash;
        assembly {
            tstore(FINAL_HASH_SLOT, finalHash)
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
                    attestation.finalHash,
                    attestation.validator,
                    keccak256(abi.encode(attestation.calls)),
                    keccak256(abi.encode(attestation.recipients))
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
            executionHash := tload(EXECUTION_HASH_SLOT)
        }

        // If there is no attestation and the bypass flag is not used,
        // then the transaction should revert.
        if (uint160(getCurrentAttester()) == 0) {
            if (BYPASS_FLAG.code.length == 0) {
                revert AttestationRequired();
            }
        }

        executionHash = executionHashFrom(checkpointHash, msg.sender, executionHash);
        emit CheckpointExecuted(address(this), executionHash);
        assembly {
            tstore(EXECUTION_HASH_SLOT, executionHash)
        }
    }

    function executionHashFrom(bytes32 checkpointHash, address caller, bytes32 executionHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(checkpointHash, caller, executionHash));
    }

    function validateExecution() public {
        bytes32 finalHash;
        bytes32 executionHash;
        assembly {
            finalHash := tload(FINAL_HASH_SLOT)
            executionHash := tload(EXECUTION_HASH_SLOT)
        }
        if (finalHash != executionHash) {
            revert ValidationFailed(address(this), executionHash);
        }
        emptyTransientStorage();
    }

    function emptyTransientStorage() internal {
        assembly {
            tstore(ATTESTER_SLOT, 0)
            tstore(FINAL_HASH_SLOT, 0)
            tstore(EXECUTION_HASH_SLOT, 0)
            tstore(DEPTH_SLOT, 0)
        }
    }
}
