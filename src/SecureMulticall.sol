// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/Multicall.sol";
import "./SecurityValidator.sol";

// This is for arbitrary contracts to support attested user calls.
abstract contract SecureMulticall is Multicall {
    SecurityValidator trustedValidator;

    constructor(SecurityValidator _trustedValidator) {
        trustedValidator = _trustedValidator;
    }

    function secureMulticall(bytes32 attestationHash, bytes calldata attestationSignature, bytes[] calldata data)
        public
    {
        trustedValidator.saveAttestation(attestationHash, attestationSignature);
        this.multicall(data);
        trustedValidator.validateAttestation();
    }
}
