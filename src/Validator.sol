// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

uint256 constant ATTESTATION_HASH_SLOT = 0;
uint256 constant APPROVAL_HASH_SLOT = 1;

contract Validator {
	function saveAttestation(bytes32 attestationHash, bytes calldata signature) public {
		// TODO: Verify signature.

		assembly {
			tstore(ATTESTATION_HASH_SLOT, attestationHash)
		}
	}

	function executeCheckpoint(bytes32 checkpointHash) public {
		bytes32 latestApprovalHash;
		assembly {
			latestApprovalHash := tload(APPROVAL_HASH_SLOT)
		}
		bytes32 currentApprovalHash = keccak256(abi.encode(checkpointHash, msg.sender, latestApprovalHash));
		assembly {
			tstore(APPROVAL_HASH_SLOT, currentApprovalHash)
		}
	}

	function validateAttestation() public {
		bytes32 attestationHash;
		bytes32 latestApprovalHash;
		assembly {
			attestationHash := tload(ATTESTATION_HASH_SLOT)
			latestApprovalHash := tload(APPROVAL_HASH_SLOT)
		}
		require(attestationHash == latestApprovalHash);
	}

	function checkpointsDisabled() internal view returns (bool) {
		return (BYPASS_FLAG.code.length > 0);
	}
}
