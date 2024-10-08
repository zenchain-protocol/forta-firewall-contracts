// SPDX-License-Identifier: UNLICENSED
// See Forta Network License: https://github.com/forta-network/forta-firewall-contracts/blob/master/LICENSE.md

pragma solidity ^0.8.25;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {IFirewallAccess} from "./FirewallAccess.sol";
import {FirewallPermissions} from "./FirewallPermissions.sol";
import {ISecurityValidator, Attestation} from "./SecurityValidator.sol";
import {Quantization} from "./Quantization.sol";

/**
 * @notice A checkpoint is a configurable point in code that activates in different conditions and
 * does security checks before proceeding with the rest of the execution.
 */
struct Checkpoint {
    /// @notice The value to compare against an incoming function argument.
    uint192 threshold;
    /**
     * @notice Defines the expected start position of the incoming argument in the call data.
     * This is needed in some integration cases when the reference is found directly from call data
     * bytes.
     */
    uint16 refStart;
    /**
     * @notice Defines the expected end position of the incoming argument in the call data.
     * This is needed in some integration cases when the reference is found directly from call data
     * bytes.
     */
    uint16 refEnd;
    /**
     * @notice Defines the type of checkpoint activation (see types below).
     */
    Activation activation;
    /**
     * @notice This is for relying on tx.origin instead of hash-based checkpoint execution.
     */
    bool trustedOrigin;
}

/// @notice Checkpoint activation modes.
enum Activation {
    /// @notice The default activation value for an unset checkpoint, which should mean "no security checks".
    Inactive,
    /// @notice The checkpoint is blocked by default.
    AlwaysBlocked,
    /// @notice Every call to the integrated function should require security checks.
    AlwaysActive,
    /// @notice Security checks are only required if a specific function argument exceeds the threshold.
    ConstantThreshold,
    /// @notice For adding up all intercepted values by the same checkpoint before comparing with the threshold.
    AccumulatedThreshold
}

interface IFirewall {
    function updateFirewallConfig(
        ISecurityValidator _validator,
        ICheckpointHook _checkpointHook,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) external;

    function getFirewallConfig()
        external
        view
        returns (
            ISecurityValidator _validator,
            ICheckpointHook _checkpointHook,
            bytes32 _attesterControllerId,
            IFirewallAccess _firewallAccess
        );

    function setCheckpoint(bytes4 selector, Checkpoint memory checkpoint) external;

    function setCheckpointActivation(bytes4 selector, Activation activation) external;

    function getCheckpoint(bytes4 selector) external view returns (uint192, uint16, uint16, Activation, bool);

    function attestedCall(Attestation calldata attestation, bytes calldata attestationSignature, bytes calldata data)
        external
        returns (bytes memory);
}

interface IAttesterInfo {
    event AttesterControllerUpdated(bytes32 indexed attesterControllerId);

    function getAttesterControllerId() external view returns (bytes32);
}

enum HookResult {
    Inconclusive,
    ForceActivation,
    ForceDeactivation
}

/// @notice An interface to support custom configurations per executed checkpoint.
interface ICheckpointHook {
    function handleCheckpoint(address caller, bytes4 selector, uint256 ref) external view returns (HookResult);
}

/**
 * @notice Firewall is a base contract which provides protection against exploits.
 * It keeps a collection of configurable checkpoints per function, in its namespaced storage,
 * and makes available internal functions to the child contract in order to help intercept
 * function calls.
 *
 * When a function call is intercepted, one of the arguments is used as a reference to compare
 * with a configured threshold. Exceeding the threshold
 */
abstract contract Firewall is IFirewall, IAttesterInfo, FirewallPermissions {
    using StorageSlot for bytes32;
    using Quantization for uint256;

    error InvalidActivationType();
    error UntrustedAttester(address attester);
    error CheckpointBlocked();

    event SecurityConfigUpdated(ISecurityValidator indexed validator, IFirewallAccess indexed firewallAccess);
    event SupportsTrustedOrigin(address indexed firewall);

    struct FirewallStorage {
        ISecurityValidator validator;
        ICheckpointHook checkpointHook;
        bytes32 attesterControllerId;
        mapping(bytes4 funcSelector => Checkpoint checkpoint) checkpoints;
    }

    /// @custom:storage-location erc7201:forta.Firewall.storage
    bytes32 private constant STORAGE_SLOT = 0x993f81a6354aa9d98fa5ac249e63371dfc7f5589eeb8a5b081145c8ed289c400;

    /**
     * @notice Updates the firewall config.
     * @param _validator Validator used for checkpoint execution calls.
     * @param _checkpointHook Checkpoint hook contract which is called before every checkpoint.
     * @param _attesterControllerId The ID of the external controller which keeps settings related
     * to the attesters.
     * @param _firewallAccess Firewall access controller.
     */
    function updateFirewallConfig(
        ISecurityValidator _validator,
        ICheckpointHook _checkpointHook,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) public virtual onlyFirewallAdmin {
        _updateFirewallConfig(_validator, _checkpointHook, _attesterControllerId, _firewallAccess);
    }

    /**
     * @notice Initializes the firewall config for the first time.
     * @param _validator The security validator which the firewall calls for saving
     * the attestation and executing checkpoints.
     * @param _checkpointHook Checkpoint hook contract which is called before every checkpoint.
     * @param _attesterControllerId The id of the controller that lives on Forta chain. Attesters
     * regards this value to find out the settings for this contract before creating an attestation.
     * @param _firewallAccess The access control contract that knows the accounts which can manage
     * the settings of a firewall.
     */
    function _updateFirewallConfig(
        ISecurityValidator _validator,
        ICheckpointHook _checkpointHook,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) internal virtual {
        FirewallStorage storage $ = _getFirewallStorage();
        $.validator = _validator;
        $.checkpointHook = _checkpointHook;
        $.attesterControllerId = _attesterControllerId;
        _updateFirewallAccess(_firewallAccess);
        emit SecurityConfigUpdated(_validator, _firewallAccess);
        emit AttesterControllerUpdated(_attesterControllerId);
    }

    /**
     * @notice Returns the firewall configuration.
     * @return validator The security validator which the firewall calls for saving
     * the attestation and executing checkpoints.
     * @return checkpointHook Checkpoint hook contract which is called before every checkpoint.
     * @return attesterControllerId The id of the controller that lives on Forta chain. Attesters
     * regards this value to find out the settings for this contract before creating an attestation.
     * @return firewallAccess The access control contract that knows the accounts which can manage
     * the settings of a firewall.
     */
    function getFirewallConfig()
        public
        view
        returns (
            ISecurityValidator validator,
            ICheckpointHook checkpointHook,
            bytes32 attesterControllerId,
            IFirewallAccess firewallAccess
        )
    {
        FirewallStorage storage $ = _getFirewallStorage();
        firewallAccess = _getFirewallAccess();
        return ($.validator, $.checkpointHook, $.attesterControllerId, firewallAccess);
    }

    /**
     * @notice Returns the attester controller id from the configuration.
     */
    function getAttesterControllerId() public view returns (bytes32) {
        return _getFirewallStorage().attesterControllerId;
    }

    /**
     * @notice Sets checkpoint values for given function selector, call data byte range
     * and with given threshold type.
     * @param selector Selector of the function.
     * @param checkpoint Checkpoint data.
     */
    function setCheckpoint(bytes4 selector, Checkpoint memory checkpoint) public virtual onlyCheckpointManager {
        require(checkpoint.refStart <= checkpoint.refEnd, "refStart is larger than refEnd");
        _getFirewallStorage().checkpoints[selector] = checkpoint;
    }

    /**
     * @notice Sets the checkpoint activation type.
     * @param selector Selector of the function.
     * @param activation Activation type.
     */
    function setCheckpointActivation(bytes4 selector, Activation activation) public virtual onlyCheckpointManager {
        _getFirewallStorage().checkpoints[selector].activation = activation;
    }

    /**
     * @notice Gets the checkpoint values for given function selector.
     * @param selector Selector of the function.
     */
    function getCheckpoint(bytes4 selector) public view virtual returns (uint192, uint16, uint16, Activation, bool) {
        Checkpoint storage checkpoint = _getFirewallStorage().checkpoints[selector];
        return (
            checkpoint.threshold,
            checkpoint.refStart,
            checkpoint.refEnd,
            checkpoint.activation,
            checkpoint.trustedOrigin
        );
    }

    /**
     * @notice Helps write an attestation and call any function of this contract.
     * @param attestation The set of fields that correspond to and enable the execution of call(s)
     * @param attestationSignature Signature of EIP-712 message
     * @param data Call data which contains the function selector and the encoded arguments
     */
    function attestedCall(Attestation calldata attestation, bytes calldata attestationSignature, bytes calldata data)
        public
        returns (bytes memory)
    {
        _getFirewallStorage().validator.saveAttestation(attestation, attestationSignature);
        return Address.functionDelegateCall(address(this), data);
    }

    function _secureExecution() internal virtual {
        Checkpoint storage checkpoint = _getFirewallStorage().checkpoints[msg.sig];
        require(checkpoint.refEnd <= msg.data.length, "refEnd too large for slicing");
        if (msg.sig == 0 || (checkpoint.refEnd == 0 && checkpoint.refStart == 0)) {
            /// Ether transaction or paid transaction with no ref range: use msg.value as ref
            _secureExecution(msg.sender, msg.sig, msg.value);
        } else if (checkpoint.refEnd - checkpoint.refStart > 32) {
            /// Support larger data ranges as direct input hashes instead of deriving a reference.
            bytes calldata byteRange = msg.data[checkpoint.refStart:checkpoint.refEnd];
            bytes32 input = keccak256(byteRange);
            _executeCheckpoint(checkpoint, input, msg.sig);
        } else {
            bytes calldata byteRange = msg.data[checkpoint.refStart:checkpoint.refEnd];
            uint256 ref = uint256(bytes32(byteRange));
            _secureExecution(msg.sender, msg.sig, ref);
        }
    }

    function _secureExecution(address caller, bytes4 selector, uint256 ref) internal virtual {
        Checkpoint storage checkpoint = _getFirewallStorage().checkpoints[selector];
        bool ok;
        (ref, ok) = _checkpointActivated(checkpoint, caller, selector, ref);
        if (ok) _executeCheckpoint(checkpoint, bytes32(ref.quantize()), selector);
    }

    function _secureExecution(bytes4 selector, bytes32 input) internal virtual {
        Checkpoint storage checkpoint = _getFirewallStorage().checkpoints[selector];
        bool ok = _checkpointActivated(checkpoint);
        if (ok) _executeCheckpoint(checkpoint, input, selector);
    }

    function _executeCheckpoint(Checkpoint storage checkpoint, bytes32 input, bytes4 selector) private {
        FirewallStorage storage $ = _getFirewallStorage();

        /// Short-circuit if the trusted origin pattern is supported and is available.
        /// Otherwise, continue with checkpoint execution.
        if (_isTrustedOrigin(checkpoint)) return;

        $.validator.executeCheckpoint(keccak256(abi.encode(msg.sender, address(this), selector, input)));

        /// Ensure first that the current attester can be trusted.
        /// If the current attester is zero address, let the security validator deal with that.
        address currentAttester = $.validator.getCurrentAttester();
        if (currentAttester != address(0) && !_isTrustedAttester(currentAttester)) {
            revert UntrustedAttester(currentAttester);
        }
    }

    function _checkpointActivated(Checkpoint storage checkpoint, address caller, bytes4 selector, uint256 ref)
        private
        returns (uint256, bool)
    {
        ICheckpointHook checkpointHook = _getFirewallStorage().checkpointHook;
        if (address(checkpointHook) != address(0)) {
            HookResult result = checkpointHook.handleCheckpoint(caller, selector, ref);
            if (result == HookResult.ForceActivation) return (ref, true);
            if (result == HookResult.ForceDeactivation) return (ref, false);
            // Otherwise, just keep on with default checkpoint configuration and logic.
        }
        if (checkpoint.activation == Activation.Inactive) return (ref, false);
        if (checkpoint.activation == Activation.AlwaysBlocked) revert CheckpointBlocked();
        if (checkpoint.activation == Activation.AlwaysActive) return (ref, true);
        if (checkpoint.activation == Activation.ConstantThreshold) return (ref, ref >= checkpoint.threshold);
        if (checkpoint.activation != Activation.AccumulatedThreshold) {
            revert InvalidActivationType();
        }
        /// Continue with the "accumulated threshold" logic.
        bytes32 slot = keccak256(abi.encode(selector, msg.sender));
        uint256 acc = StorageSlot.tload(slot.asUint256());
        acc += ref;
        StorageSlot.tstore(slot.asUint256(), acc);
        return (ref, acc >= checkpoint.threshold);
    }

    function _checkpointActivated(Checkpoint storage checkpoint) private view returns (bool) {
        if (checkpoint.activation == Activation.Inactive) return false;
        if (checkpoint.activation == Activation.AlwaysBlocked) revert CheckpointBlocked();
        if (checkpoint.activation == Activation.AlwaysActive) return true;
        return false;
    }

    function _isTrustedOrigin(Checkpoint storage checkpoint) internal returns (bool) {
        if (checkpoint.trustedOrigin) {
            emit SupportsTrustedOrigin(address(this));
            return _isTrustedAttester(tx.origin);
        }
        return false;
    }

    function _getFirewallStorage() internal pure virtual returns (FirewallStorage storage $) {
        assembly {
            $.slot := STORAGE_SLOT
        }
    }
}
