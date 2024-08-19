// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ISecurityAccess} from "./SecurityAccessControl.sol";
import {SecurityAccessChecker} from "./SecurityAccessChecker.sol";
import {BYPASS_FLAG, ISecurityValidator, Attestation} from "./SecurityValidator.sol";
import {ITrustedAttesters} from "./TrustedAttesters.sol";
import {Sensitivity} from "./Sensitivity.sol";

struct Checkpoint {
    uint192 threshold;
    uint16 refStart;
    uint16 refEnd;
    uint8 activation;
    uint8 trustedOrigin;
}

uint8 constant ACTIVATION_UNDEFINED = 0;
uint8 constant ACTIVATION_ALWAYS_BLOCKED = 1;
uint8 constant ACTIVATION_ALWAYS_ACTIVE = 2;
uint8 constant ACTIVATION_CONSTANT_THRESHOLD = 3;
uint8 constant ACTIVATION_ACCUMULATED_THRESHOLD = 4;

interface ISecurityLogic {
    function updateSecurityConfig(
        ISecurityValidator _validator,
        ITrustedAttesters _trustedAttesters,
        bytes32 _attesterControllerId,
        ISecurityAccess _securityAccess
    ) external;

    function getSecurityConfig()
        external
        view
        returns (
            ISecurityValidator _validator,
            ITrustedAttesters _trustedAttesters,
            bytes32 _attesterControllerId,
            ISecurityAccess _securityAccess
        );

    function setCheckpoint(string memory funcSig, Checkpoint memory checkpoint) external;

    function getCheckpoint(string memory funcSig) external view returns (uint192, uint16, uint16, uint8, uint8);

    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) external;
}

abstract contract SecurityLogic is ISecurityLogic, SecurityAccessChecker, Initializable, Multicall {
    using StorageSlot for bytes32;
    using Sensitivity for uint256;

    error AlreadyInitialized();
    error InvalidThresholdType();
    error UntrustedAttester(address attester);
    error CheckpointBlocked();

    event SecurityConfigUpdated(
        ISecurityValidator _validator,
        ITrustedAttesters _trustedAttesters,
        bytes32 _attesterControllerId,
        ISecurityAccess _securityAccess
    );
    event SupportsTrustedOrigin(address);

    struct SecurityStorage {
        ISecurityValidator validator;
        ITrustedAttesters trustedAttesters;
        bytes32 attesterControllerId;
        mapping(bytes4 => Checkpoint) checkpoints;
    }

    /// @custom:storage-location erc7201:forta.SecurityLogic.storage
    bytes32 private constant STORAGE_SLOT = 0x485985ccdcd1f70058cc1a5c2b59855a5c9bf4fd2d95c7e42c610811e088ff00;

    /**
     * @notice Initializes the security config for the first time.
     * @param _validator The security validator which the security proxy calls for saving
     * the attestation and executing checkpoints.
     */
    function updateSecurityConfig(
        ISecurityValidator _validator,
        ITrustedAttesters _trustedAttesters,
        bytes32 _attesterControllerId,
        ISecurityAccess _securityAccess
    ) public virtual onlySecurityAdmin {
        _updateSecurityConfig(_validator, _trustedAttesters, _attesterControllerId, _securityAccess);
    }

    /**
     * @notice Initializes the security config for the first time.
     * @param _validator The security validator which the security proxy calls for saving
     * the attestation and executing checkpoints.
     */
    function _updateSecurityConfig(
        ISecurityValidator _validator,
        ITrustedAttesters _trustedAttesters,
        bytes32 _attesterControllerId,
        ISecurityAccess _securityAccess
    ) internal virtual {
        SecurityStorage storage $ = _getSecurityStorage();
        $.validator = _validator;
        $.trustedAttesters = _trustedAttesters;
        $.attesterControllerId = _attesterControllerId;
        _updateSecurityAccess(_securityAccess);
        emit SecurityConfigUpdated(_validator, _trustedAttesters, _attesterControllerId, _securityAccess);
    }

    function getSecurityConfig()
        public
        view
        returns (
            ISecurityValidator _validator,
            ITrustedAttesters _trustedAttesters,
            bytes32 _attesterControllerId,
            ISecurityAccess _securityAccess
        )
    {
        SecurityStorage storage $ = _getSecurityStorage();
        ISecurityAccess securityAccess = _getSecurityAccess();
        return ($.validator, $.trustedAttesters, $.attesterControllerId, securityAccess);
    }

    /**
     * @notice Sets checkpoint values for given function signature, call data byte range
     * and with given threshold type.
     * @param funcSig Signature of the function.
     * @param checkpoint Checkpoint data.
     */
    function setCheckpoint(string memory funcSig, Checkpoint memory checkpoint) public virtual onlyCheckpointManager {
        _getSecurityStorage().checkpoints[_toSelector(funcSig)] = checkpoint;
    }

    /**
     * @notice Gets the checkpoint values for given function signature.
     * @param funcSig Signature of the function.
     */
    function getCheckpoint(string memory funcSig) public view virtual returns (uint192, uint16, uint16, uint8, uint8) {
        Checkpoint storage checkpoint = _getSecurityStorage().checkpoints[_toSelector(funcSig)];
        return (
            checkpoint.threshold,
            checkpoint.refStart,
            checkpoint.refEnd,
            checkpoint.activation,
            checkpoint.trustedOrigin
        );
    }

    /**
     * @notice A helper function to call the security validator to save the attestation first
     * before proceeding with the user call. This should typically be the first call in a
     * multicall.
     * @param attestation The security attestation - see SecurityValidator
     * @param attestationSignature The security attestation signature - see SecurityValidator
     */
    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) public {
        _getSecurityStorage().validator.saveAttestation(attestation, attestationSignature);
    }

    /**
     * @notice Helps write an attestation and call any function of this contract. This is an alternative
     * to using a multicall that has saveAttestation().
     * @param attestation The set of fields that correspond to and enable the execution of call(s)
     * @param attestationSignature Signature of EIP-712 message
     * @param data Call data which contains the function selector and the encoded arguments
     */
    function attestedCall(Attestation calldata attestation, bytes calldata attestationSignature, bytes calldata data)
        public
    {
        _getSecurityStorage().validator.saveAttestation(attestation, attestationSignature);
        Address.functionDelegateCall(address(this), data);
    }

    function _secureExecution() internal virtual {
        Checkpoint storage checkpoint = _getSecurityStorage().checkpoints[msg.sig];
        (uint256 ref, bool ok) = _checkpointActivated(checkpoint);
        if (ok) _executeCheckpoint(ref, checkpoint.trustedOrigin);
    }

    function _secureExecution(uint256 ref) internal virtual {
        Checkpoint storage checkpoint = _getSecurityStorage().checkpoints[msg.sig];
        bool ok = _checkpointActivatedWithRef(ref, checkpoint);
        if (ok) _executeCheckpoint(ref, checkpoint.trustedOrigin);
    }

    function _executeCheckpoint(uint256 ref, uint256 trustedOrigin) private {
        SecurityStorage storage $ = _getSecurityStorage();

        /// Short-circuit if the trusted origin pattern is supported and
        /// is available.
        if (trustedOrigin == 1) {
            emit SupportsTrustedOrigin(address(this));
            if ($.trustedAttesters.isTrustedAttester(tx.origin)) {
                return;
            }
        }
        /// Otherwise, fall back to the checkpoint execution.

        /// Ensure first that the current attester can be trusted.
        if (BYPASS_FLAG.code.length == 0) {
            address currentAttester = $.validator.getCurrentAttester();
            if (!$.trustedAttesters.isTrustedAttester(currentAttester)) {
                revert UntrustedAttester(currentAttester);
            }
        }

        $.validator.executeCheckpoint(
            keccak256(abi.encode(msg.sender, address(this), msg.sig, ref.reduceSensitivity()))
        );
    }

    function _checkpointActivated(Checkpoint storage checkpoint) private returns (uint256, bool) {
        bytes calldata byteRange = msg.data[checkpoint.refStart:checkpoint.refEnd];
        uint256 ref = uint256(bytes32(byteRange));
        return (ref, _checkpointActivatedWithRef(ref, checkpoint));
    }

    function _checkpointActivatedWithRef(uint256 ref, Checkpoint storage checkpoint) private returns (bool) {
        if (checkpoint.activation == ACTIVATION_UNDEFINED) return false;
        if (checkpoint.activation == ACTIVATION_ALWAYS_BLOCKED) revert CheckpointBlocked();
        if (checkpoint.activation == ACTIVATION_ALWAYS_ACTIVE) return true;
        if (checkpoint.activation == ACTIVATION_CONSTANT_THRESHOLD) return ref >= checkpoint.threshold;
        if (checkpoint.activation != ACTIVATION_ACCUMULATED_THRESHOLD) {
            revert InvalidThresholdType();
        }
        bytes32 slot = keccak256(abi.encode(msg.sig, msg.sender));
        uint256 acc = StorageSlot.tload(slot.asUint256());
        acc += ref;
        StorageSlot.tstore(slot.asUint256(), acc);
        return acc >= checkpoint.threshold;
    }

    function _getSecurityStorage() internal pure virtual returns (SecurityStorage storage $) {
        assembly {
            $.slot := STORAGE_SLOT
        }
    }

    function _toSelector(string memory funcSig) private pure returns (bytes4) {
        return bytes4(keccak256(bytes(funcSig)));
    }
}
