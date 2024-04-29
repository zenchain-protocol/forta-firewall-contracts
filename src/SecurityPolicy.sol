// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "./SecurityValidator.sol";

contract SecurityPolicy {
	SecurityValidator trustedValidator;

	constructor(SecurityValidator _trustedValidator) {
		trustedValidator = _trustedValidator;
	}

	function executeCheckpoint(bytes32 checkpointId, bytes32 checkpointHash, uint256 thresholdAmount) public {
		// TODO: Take into account the thresholds later.

		trustedValidator.executeCheckpoint(checkpointHash);
	}
}
