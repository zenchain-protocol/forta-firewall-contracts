// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ISecurityValidator, Attestation} from "./SecurityValidator.sol";

interface ISecurityProxy {
    function initializeSecurityProxy(address _admin, ISecurityValidator _validator) external;
    function configureSecurityProxy(address _admin, ISecurityValidator _validator) external;
    function proxiableUUID() external view returns (bytes32);
    function upgradeNextAndCall(address newImplementation, bytes memory data) external;
    function updateSecurityProxyAdmin(address newAdmin) external;
    function setCheckpointThreshold(string memory funcSig, uint256 threshold) external;
    function getCheckpointThreshold(string memory funcSig) external view returns (uint256);
}

contract SecurityProxy is Proxy, Multicall {
    error AlreadyInitialized();
    error UpgradeNonPayable();

    struct Storage {
        address admin;
        ISecurityValidator validator;
        mapping(bytes4 => uint256) thresholds;
    }

    /// @custom:storage-location erc7201:forta.SecurityProxy.next.implementation
    bytes32 internal constant NEXT_IMPLEMENTATION_SLOT =
        0xd545e8ffcb746253c779f78291104681c5efe4255000031cc6e3a635e0223400;

    /// @custom:storage-location erc7201:forta.SecurityProxy.storage
    bytes32 internal constant STORAGE_SLOT =
        0xacf391f95ab0e100b767a4030b45282ec897f2945f8bc39124a323658cc84800;

    modifier onlySecurityProxyAdmin() {
        Storage storage $ = _getStorage();
        require(msg.sender == $.admin);
        _;
    }

    /**
     * @notice Initializes the security proxy for the first time.
     * @param _admin The security proxy admin which can set the next contract in chain
     * and adjust thresholds.
     * @param _validator The security validator which the security proxy calls for saving
     * the attestation and executing checkpoints.
     */
    function initializeSecurityProxy(address _admin, ISecurityValidator _validator) public {
        Storage storage $ = _getStorage();
        if ($.admin != address(0)) revert AlreadyInitialized();
        $.admin = _admin;
        $.validator = _validator;
    }

    /**
     * @notice Initializes the security proxy for the first time.
     * @param _admin The security proxy admin which can set the next contract in chain
     * and adjust thresholds.
     * @param _validator The security validator which the security proxy calls for saving
     * the attestation and executing checkpoints.
     */
    function configureSecurityProxy(address _admin, ISecurityValidator _validator) public onlySecurityProxyAdmin {
        Storage storage $ = _getStorage();
        $.admin = _admin;
        $.validator = _validator;
    }

    /**
     * @notice Sets the next implementation contract which the fallback function will delegatecall to.
     * Copied and adapted from OpenZeppelin ERC1967Utils.upgradeToAndCall().
     * @param newImplementation The next implementation contract
     * @param data Call data
     */
    function upgradeNextAndCall(address newImplementation, bytes memory data)
        public
        payable
        onlySecurityProxyAdmin
    {
        StorageSlot.getAddressSlot(NEXT_IMPLEMENTATION_SLOT).value = newImplementation;
        if (data.length > 0) {
            Address.functionDelegateCall(newImplementation, data);
        } else {
            _checkNonPayable();
        }
    }

    /**
     * @notice Allows security proxy admin to update to a new admin.
     * @param newAdmin New admin address
     */
    function updateSecurityProxyAdmin(address newAdmin) public onlySecurityProxyAdmin {
        _getStorage().admin = newAdmin;
    }

    /**
     * @notice Sets a checkpoint threshold for given function signature, call data byte range
     * and with given threshold type.
     * @param funcSig Signature of the function.
     * TODO: Add other args.
     */
    function setCheckpointThreshold(string memory funcSig, uint256 threshold) public onlySecurityProxyAdmin {
        _getStorage().thresholds[bytes4(keccak256(bytes(funcSig)))] = threshold;
    }

    /**
     * @notice Gets the checkpoint threshold for given function signature.
     * @param funcSig Signature of the function.
     */
    function getCheckpointThreshold(string memory funcSig) public view returns (uint256) {
        return _getStorage().thresholds[bytes4(keccak256(bytes(funcSig)))];
    }

    /**
     * @notice A helper function to call the security validator to save the attestation first
     * before proceeding with the user call. This should typically be the first call in a
     * multicall.
     * @param attestation The security attestation - see SecurityValidator
     * @param attestationSignature The security attestation signature - see SecurityValidator
     */
    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) public {
        _getStorage().validator.saveAttestation(attestation, attestationSignature);
    }

    /// @inheritdoc Proxy
    function _implementation() internal view override returns (address) {
        return StorageSlot.getAddressSlot(NEXT_IMPLEMENTATION_SLOT).value;
    }

    /// @notice TODO: Make sure to validate the current attester against an attester registry.
    /// @inheritdoc Proxy
    function _fallback() internal override {
        Storage storage $ = _getStorage();
        (uint256 ref, bool ok) = _thresholdActivated();
        if (ok) {
            $.validator.executeCheckpoint(keccak256(abi.encode(msg.sender, address(this), msg.sig, ref)));
        }
        super._fallback();
    }

    /// TODO: This should be able to read other arguments.
    /// TODO: This should consider constant and accumulated threshold types.
    function _thresholdActivated() internal view virtual returns (uint256, bool) {
        Storage storage $ = _getStorage();
        uint256 threshold = $.thresholds[msg.sig];
        /// TODO: Get byte range start and end from threshold value.
        if (threshold == 0) {
            return (0, false);
        }
        if (threshold == 1) {
            return (1, true);
        }
        /// TODO: Use the byte range here.
        bytes calldata byteRange = msg.data[4:36];
        uint256 ref = uint256(bytes32(byteRange));
        if (ref < threshold) {
            return (0, false);
        }
        return (_scaleDownRef(ref), true);
    }

    /// TODO: Use log1.01 here or similar.
    function _scaleDownRef(uint256 ref) internal view virtual returns (uint256) {
        return ref;
    }

    function _getStorage() internal pure returns (Storage storage $) {
        assembly {
            $.slot := STORAGE_SLOT
        }
    }

    /**
     * @dev Reverts if `msg.value` is not zero. It can be used to avoid `msg.value` stuck in the contract
     * if an upgrade doesn't perform an initialization call.
     * Copied from OpenZeppelin ERC1967Utils library.
     */
    function _checkNonPayable() private {
        if (msg.value > 0) {
            revert UpgradeNonPayable();
        }
    }

    receive() external payable {}
}
