// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
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

    function setCheckpoint(string memory funcSig, Checkpoint memory checkpoint) external;

    function setCheckpoint(bytes4 selector, Checkpoint memory checkpoint) external;

    function setCheckpointActivation(string memory funcSig, Activation activation) external;

    function setCheckpointActivation(bytes4 selector, Activation activation) external;

    function getCheckpoint(string memory funcSig) external view returns (uint192, uint16, uint16, Activation, bool);

    function getCheckpoint(bytes4 selector) external view returns (uint192, uint16, uint16, Activation, bool);

    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) external;
}

interface IAttesterInfo {
    event AttesterControllerUpdated(bytes32 attesterControllerId);

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
abstract contract Firewall is IFirewall, IAttesterInfo, FirewallPermissions, Initializable {
    using StorageSlot for bytes32;
    using Quantization for uint256;

    error AlreadyInitialized();
    error InvalidThresholdType();
    error UntrustedAttester(address attester);
    error CheckpointBlocked();

    event SecurityConfigUpdated(ISecurityValidator validator, IFirewallAccess firewallAccess);
    event SupportsTrustedOrigin(address);

    struct FirewallStorage {
        ISecurityValidator validator;
        ICheckpointHook checkpointHook;
        bytes32 attesterControllerId;
        mapping(bytes4 => Checkpoint) checkpoints;
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
     * @notice Sets checkpoint values for given function signature, call data byte range
     * and with given threshold type.
     * @param funcSig Signature of the function.
     * @param checkpoint Checkpoint data.
     */
    function setCheckpoint(string memory funcSig, Checkpoint memory checkpoint) public virtual onlyCheckpointManager {
        setCheckpoint(_toSelector(funcSig), checkpoint);
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
     * @param funcSig Signature of the function.
     * @param activation Activation type.
     */
    function setCheckpointActivation(string memory funcSig, Activation activation)
        public
        virtual
        onlyCheckpointManager
    {
        return setCheckpointActivation(_toSelector(funcSig), activation);
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
     * @notice Gets the checkpoint values for given function signature.
     * @param funcSig Signature of the function.
     */
    function getCheckpoint(string memory funcSig)
        public
        view
        virtual
        returns (uint192, uint16, uint16, Activation, bool)
    {
        return getCheckpoint(_toSelector(funcSig));
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
     * @notice A helper function to call the security validator to save the attestation first
     * before proceeding with the user call. This should typically be the first call in a
     * multicall.
     * @param attestation The security attestation - see SecurityValidator
     * @param attestationSignature The security attestation signature - see SecurityValidator
     */
    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) public {
        _getFirewallStorage().validator.saveAttestation(attestation, attestationSignature);
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
        _getFirewallStorage().validator.saveAttestation(attestation, attestationSignature);
        Address.functionDelegateCall(address(this), data);
    }

    function _secureExecution() internal virtual {
        Checkpoint storage checkpoint = _getFirewallStorage().checkpoints[msg.sig];
        require(checkpoint.refEnd <= msg.data.length, "refEnd too large for slicing");
        bytes calldata byteRange = msg.data[checkpoint.refStart:checkpoint.refEnd];
        uint256 ref = uint256(bytes32(byteRange));
        _secureExecution(msg.sender, msg.sig, ref);
    }

    function _secureExecution(address caller, bytes4 selector, uint256 ref) internal virtual {
        Checkpoint storage checkpoint = _getFirewallStorage().checkpoints[selector];
        bool ok;
        (ref, ok) = _checkpointActivated(caller, selector, ref, checkpoint);
        if (ok) _executeCheckpoint(ref, selector, checkpoint.trustedOrigin);
    }

    function _executeCheckpoint(uint256 ref, bytes4 selector, bool trustedOrigin) private {
        FirewallStorage storage $ = _getFirewallStorage();

        /// Short-circuit if the trusted origin pattern is supported and
        /// is available.
        if (trustedOrigin) {
            emit SupportsTrustedOrigin(address(this));
            if (_isTrustedAttester(tx.origin)) {
                return;
            }
        }
        /// Otherwise, fall back to the checkpoint execution.

        /// Ensure first that the current attester can be trusted.
        /// If the current attester is zero address, let the security validator deal with that.
        address currentAttester = $.validator.getCurrentAttester();
        if (currentAttester != address(0) && !_isTrustedAttester(currentAttester)) {
            revert UntrustedAttester(currentAttester);
        }

        $.validator.executeCheckpoint(keccak256(abi.encode(msg.sender, address(this), selector, ref.quantize())));
    }

    function _checkpointActivated(address caller, bytes4 selector, uint256 ref, Checkpoint storage checkpoint)
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
        if (checkpoint.activation == Activation.AlwaysActive) return (1, true); // special case: simplify ref for checkpoint stability
        if (checkpoint.activation == Activation.ConstantThreshold) return (ref, ref >= checkpoint.threshold);
        if (checkpoint.activation != Activation.AccumulatedThreshold) {
            revert InvalidThresholdType();
        }
        /// Continue with the "accumulated threshold" logic.
        bytes32 slot = keccak256(abi.encode(selector, msg.sender));
        uint256 acc = StorageSlot.tload(slot.asUint256());
        acc += ref;
        StorageSlot.tstore(slot.asUint256(), acc);
        return (ref, acc >= checkpoint.threshold);
    }

    function _getFirewallStorage() internal pure virtual returns (FirewallStorage storage $) {
        assembly {
            $.slot := STORAGE_SLOT
        }
    }

    function _toSelector(string memory funcSig) private pure returns (bytes4) {
        return bytes4(keccak256(bytes(funcSig)));
    }
}
