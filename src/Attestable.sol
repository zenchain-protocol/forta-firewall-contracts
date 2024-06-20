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
        _executeCheckpoint(checkpointId, referenceAmount, thresholdType);
        _;
        _exitCall();
    }

    function _executeCheckpoint(bytes32 checkpointId, uint256 referenceAmount, Threshold thresholdType) internal {
        // Outermost calls need to rely on sender and call data during hash generation
        // for checkpoint execution. This is needed for making the attestations specific to the
        // outermost user calls that initiate the chain of calls down the call stack.
        //
        // For deeper calls, using call data can make attestations fragile since the arguments
        // that are passed to intermediary calls can change depending on chain state. This is
        // not the same for outer calls which depend on the exact kind of intents the user wants
        // to execute.
        uint256 depth = policyContract.enterCall();
        if (depth == 1) {
            bytes32 callHash = keccak256(abi.encode(msg.sender, msg.data));
            policyContract.executeCheckpoint(checkpointId, callHash, referenceAmount, thresholdType);
        } else {
            policyContract.executeCheckpoint(checkpointId, bytes32(uint256(uint160(msg.sender))), referenceAmount, thresholdType);
        }
    }

    function _exitCall() internal {
        policyContract.exitCall();
    }

    function attestedCall(Attestation calldata attestation, bytes calldata attestationSignature, bytes calldata data)
        public
    {
        policyContract.saveAttestation(attestation, attestationSignature);
        Address.functionDelegateCall(address(this), data);
    }
}
