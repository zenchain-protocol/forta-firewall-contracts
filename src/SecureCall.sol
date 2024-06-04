// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/Address.sol";
import {Attestation, ISecurityValidator} from "./SecurityValidator.sol";

// This is for arbitrary contracts to support attested user calls.
abstract contract SecureCall {
    ISecurityValidator trustedValidator;

    constructor(ISecurityValidator _trustedValidator) {
        trustedValidator = _trustedValidator;
    }

    function secureCall(Attestation calldata attestation, bytes calldata attestationSignature, bytes calldata data)
        public
    {
        trustedValidator.saveAttestation(attestation, attestationSignature, msg.sender, data);
        Address.functionDelegateCall(address(this), data);
        trustedValidator.validateAttestation();
    }
}
