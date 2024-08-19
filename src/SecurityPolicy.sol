// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {SecurityLogic} from "./SecurityLogic.sol";
import {ISecurityValidator, Attestation} from "./SecurityValidator.sol";
import {ITrustedAttesters} from "./TrustedAttesters.sol";
import {ISecurityAccess} from "./SecurityAccessControl.sol";

contract SecurityPolicy is SecurityLogic {
    constructor(
        ISecurityValidator _validator,
        ITrustedAttesters _trustedAttesters,
        bytes32 _attesterControllerId,
        ISecurityAccess _securityAccess
    ) {
        _updateSecurityConfig(_validator, _trustedAttesters, _attesterControllerId, _securityAccess);
    }
}
