// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

uint256 constant ATTESTATION_HASH_SLOT = 0;
uint256 constant APPROVAL_HASH_SLOT = 1;

address constant BYPASS_FLAG = 0x0000000000000000000000000000000000f01274; // "forta" in leetspeak

uint256 constant ATTESTATION_TIMEOUT = 300; // 5m

contract SecurityValidator is EIP712 {
    error AttestationTimedOut();
    error AttestationRequired();
    error CallbackSizeMismatch();
    error CallbackFailed(uint256 index);

    struct Attestation {
        address attester;
        uint256 timestamp;
        bytes32 attestationHash;
        bytes[] callbacks;
        address[] callbackRecipients;
    }

    bytes32 private constant _ATTESTATION_TYPEHASH = keccak256(
        "Attestation(address attester,uint256 timestamp,bytes32 attestationHash,bytes[] callbacks,address[] callbackRecipients)"
    );

    // TODO: This should be access-controlled.
    address authorizedAttester;

    bool disableValidation;

    constructor(address _authorizedAttester, bool _disableValidation) EIP712("SecurityValidator", "1") {
        authorizedAttester = _authorizedAttester;
        disableValidation = _disableValidation;
    }

    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) public {
        if (isDisabled()) return;
        if (block.timestamp > attestation.timestamp && block.timestamp - attestation.timestamp > ATTESTATION_TIMEOUT) {
            revert AttestationTimedOut();
        }
        if (attestation.callbacks.length != attestation.callbackRecipients.length) {
            revert CallbackSizeMismatch();
        }
        bytes32 structHash = hashAttestation(attestation);
        address attester = ECDSA.recover(structHash, attestationSignature);

        // TODO: Instead, make an access control check later.
        require(attester == authorizedAttester);

        bytes32 attestationHash = attestation.attestationHash;
        assembly {
            tstore(ATTESTATION_HASH_SLOT, attestationHash)
        }

        for (uint256 i = 0; i < attestation.callbacks.length; i++) {
            (bool success,) = attestation.callbackRecipients[i].call(attestation.callbacks[i]);
            if (!success) revert CallbackFailed(i);
        }
    }

    function hashAttestation(Attestation calldata attestation) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    _ATTESTATION_TYPEHASH,
                    attestation.attester,
                    attestation.timestamp,
                    attestation.attestationHash,
                    keccak256(abi.encode(attestation.callbacks)),
                    keccak256(abi.encode(attestation.callbackRecipients))
                )
            )
        );
    }

    function executeCheckpoint(bytes32 checkpointHash) public {
        // If the validator is not disabled in this transaction
        // and there is no attestation, then the checkpoint execution should revert.
        //
        // Not having attestation means not having a final validateAttestation().
        // Any checkpoint should catch this case.
        if (!isDisabled() && !isAttested()) revert AttestationRequired();

        bytes32 latestApprovalHash;
        assembly {
            latestApprovalHash := tload(APPROVAL_HASH_SLOT)
        }
        bytes32 currentApprovalHash = approvalHashOf(checkpointHash, msg.sender, latestApprovalHash);
        assembly {
            tstore(APPROVAL_HASH_SLOT, currentApprovalHash)
        }
    }

    function approvalHashOf(bytes32 checkpointHash, address caller, bytes32 latestApprovalHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(checkpointHash, caller, latestApprovalHash));
    }

    function validateAttestation() public view {
        if (isDisabled()) return;

        bytes32 attestationHash;
        bytes32 latestApprovalHash;
        assembly {
            attestationHash := tload(ATTESTATION_HASH_SLOT)
            latestApprovalHash := tload(APPROVAL_HASH_SLOT)
        }
        if (attestationHash != latestApprovalHash) {
            revert AttestationRequired();
        }
    }

    function isAttested() internal view returns (bool) {
        bytes32 attestationHash;
        assembly {
            attestationHash := tload(ATTESTATION_HASH_SLOT)
        }
        return uint256(attestationHash) > 0;
    }

    function isDisabled() internal view returns (bool) {
        return disableValidation || (BYPASS_FLAG.code.length > 0);
    }
}
