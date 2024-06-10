// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/Address.sol";
import {Attestation} from "./SecurityValidator.sol";
import {Threshold, ISecurityPolicy} from "./SecurityPolicy.sol";

// This is for arbitrary contracts to support attested user calls.
abstract contract Attestable {
    ISecurityPolicy private policyContract;

    constructor(ISecurityPolicy _policyContract) {
        policyContract = _policyContract;
    }

    modifier checkpoint(bytes32 checkpointId, uint256 referenceAmount, Threshold thresholdType) {
        bool entered = _executeCheckpoint(checkpointId, referenceAmount, thresholdType);
        _;
        if (entered) policyContract.exitCall();
    }
    
    function _executeCheckpoint(bytes32 checkpointId, uint256 referenceAmount, Threshold thresholdType) internal returns (bool entered) {
        bool executing = policyContract.isExecuting();
        bool attested = policyContract.isAttested();

        if (executing || !attested) {
            policyContract.executeCheckpoint(checkpointId, referenceAmount, thresholdType);
            return false; // skip checkpoint execution
        }
        if (attested && !executing) {
            bytes32 callHash = keccak256(abi.encode(msg.sender, msg.sig, msg.data));
            policyContract.enterCall(callHash);
            return true;
        }
    }

    function _exitAttestedCall() internal {
        policyContract.exitCall();
    }

    function attestedCall(Attestation calldata attestation, bytes calldata attestationSignature, bytes calldata data)
        public
    {
        policyContract.saveAttestation(attestation, attestationSignature);
        Address.functionDelegateCall(address(this), data);
    }
}
