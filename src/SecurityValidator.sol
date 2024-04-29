// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

uint256 constant ATTESTATION_HASH_SLOT = 0;
uint256 constant APPROVAL_HASH_SLOT = 1;

address constant BYPASS_FLAG = 0x0000000000000000000000000000000000f01274; // "forta" in leetspeak

contract SecurityValidator {
	error AttestationRequired();

	address authorizedAttester;
	bool disableValidation;

	constructor(address _authorizedAttester, bool _disableValidation) {
		authorizedAttester = _authorizedAttester;
		disableValidation = _disableValidation;
	}

	function saveAttestation(bytes32 attestationHash, bytes calldata attestationSignature) public {
		if (isDisabled()) {
			return;
		}
		address attester = ECDSA.recover(attestationHash, attestationSignature);
		require(attester == authorizedAttester);
		assembly {
			tstore(ATTESTATION_HASH_SLOT, attestationHash)
		}
	}

	function executeCheckpoint(bytes32 checkpointHash) public {
		// If the validator is not disabled in this transaction
		// and there is no attestation, then the checkpoint execution should revert.
		//
		// Not having attestation means not having a final validateAttestation().
		// Any checkpoint should catch this case.
		if (!isDisabled() && !isAttested()) {
			revert AttestationRequired();
		}

		bytes32 latestApprovalHash;
		assembly {
			latestApprovalHash := tload(APPROVAL_HASH_SLOT)
		}
		bytes32 currentApprovalHash = approvalHashOf(checkpointHash, msg.sender, latestApprovalHash);
		assembly {
			tstore(APPROVAL_HASH_SLOT, currentApprovalHash)
		}
	}

	function approvalHashOf(
		bytes32 checkpointHash,
		address caller,
		bytes32 latestApprovalHash
	) public pure returns (bytes32) {
		return keccak256(abi.encode(checkpointHash, caller, latestApprovalHash));
	}

	function validateAttestation() public view {
		if (isDisabled()) {
			return;
		}

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

	function executeAttestedCall(
		bytes32 attestationHash,
		bytes calldata attestationSignature,
		address recipient,
		bytes calldata callData
	) public {
		saveAttestation(attestationHash, attestationSignature);
		(bool success,) = recipient.call(callData);
		require(success);
		validateAttestation();
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
