// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/Address.sol";
import {Attestation} from "./SecurityValidator.sol";
import {Threshold, ISecurityPolicy} from "./SecurityPolicy.sol";

/**
 * @title Attestation support for contracts
 * @notice Serves as a base contract to enable checkpoint execution and benefit from attestations.
 */
abstract contract Attestable {
    ISecurityPolicy private policyContract;

    constructor(ISecurityPolicy _policyContract) {
        policyContract = _policyContract;
    }

    /**
     * @notice A modifier which wraps a contract function with checkpoint execution.
     * @param checkpointId Identifier of the checkpoint to be executed - can be anything.
     * @param referenceAmount A value from the call that should be compared against the threshold
     * which activates the checkpoint.
     * @param thresholdType Threshold type of the checkpoint.
     */
    modifier checkpoint(bytes32 checkpointId, uint256 referenceAmount, Threshold thresholdType) {
        _executeCheckpoint(checkpointId, referenceAmount, thresholdType);
        _;
    }

    /**
     * @notice An internal function that can be used for executing arbitrary checkpoint. If usage
     * of this function is preferred over the modifier, such function must do _exitCall() before
     * returning.
     * @param checkpointId Identifier of the checkpoint to be executed - can be anything.
     * @param referenceAmount A value from the call that should be compared against the threshold
     * which activates the checkpoint.
     * @param thresholdType Threshold type of the checkpoint.
     */
    function _executeCheckpoint(bytes32 checkpointId, uint256 referenceAmount, Threshold thresholdType) internal {
        bytes32 callHash = keccak256(abi.encode(msg.sender, msg.data));
        policyContract.executeCheckpoint(checkpointId, callHash, referenceAmount, thresholdType);
    }

    /**
     * @notice Helps write an attestation and call any function of this contract.
     * @param attestation The set of fields that correspond to and enable the execution of call(s)
     * @param attestationSignature Signature of EIP-712 message
     * @param data Call data which contains the function selector and the encoded arguments
     */
    function attestedCall(Attestation calldata attestation, bytes calldata attestationSignature, bytes calldata data)
        public
    {
        policyContract.saveAttestation(attestation, attestationSignature);
        Address.functionDelegateCall(address(this), data);
    }
}
