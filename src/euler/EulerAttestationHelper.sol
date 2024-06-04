// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {ISecurityValidator} from "../SecurityValidator.sol";

interface IEVC {
    function requireVaultStatusCheck() external;
}

// This is not a vault but allows us to schedule a final hook by using
// the attestation calls.
contract EulerAttestationHelper {
    function scheduleVaultStatusCheck(IEVC evc) public {
        address validator = msg.sender;
        assembly {
            tstore(0, validator)
        }
        evc.requireVaultStatusCheck();
    }

    function checkVaultStatus() external returns (bytes4 magicValue) {
        address validator;
        assembly {
            validator := tload(0)
        }
        ISecurityValidator(validator).validateAttestation();
        assembly {
            tstore(0, 0) // reset the validator address slot
        }
        return 0x4b3d1223; // magic value signaling a success case to Euler EVC
    }
}
