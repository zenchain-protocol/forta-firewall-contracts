// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Firewall} from "./Firewall.sol";
import {ISecurityValidator, Attestation} from "./SecurityValidator.sol";
import {ITrustedAttesters} from "./TrustedAttesters.sol";
import {IFirewallAccess} from "./FirewallAccess.sol";

contract InternalFirewall is Firewall {
    constructor(
        ISecurityValidator _validator,
        ITrustedAttesters _trustedAttesters,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) {
        _updateSecurityConfig(_validator, _trustedAttesters, _attesterControllerId, _firewallAccess);
    }
}
