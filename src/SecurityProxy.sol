// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import {Attestation} from "./SecurityValidator.sol";

/// @notice The subset of the security validator functions that is required by the proxy.
interface ISecurityValidator {
    function getCurrentAttester() external view returns (address);
    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) external;
    function executeCheckpoint(bytes32 checkpointHash) external;
}

contract SecurityProxy is UUPSUpgradeable, Proxy, Multicall {
    error AlreadyInitialized();

    struct Storage {
        address admin;
        ISecurityValidator validator;
        mapping(bytes4 => uint256) thresholds;
    }

    /// @custom:storage-location erc7201:forta.SecurityProxy.implementation
    bytes32 internal constant SECURITY_PROXY_IMPLEMENTATION_SLOT =
        0x3f797f764327c91d4a886d17c1b375263d7ffb23c8519da1de25fdf4c781c000;

    /// @custom:storage-location erc7201:forta.SecurityProxy.storage
    bytes32 internal constant SECURITY_PROXY_STORAGE_SLOT =
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

    /// @notice TODO: Can this overlap with the next contracts' function in practice?
    /// It might not since it is used by the respective code that is operating.
    /// @inheritdoc UUPSUpgradeable
    function proxiableUUID() external view override notDelegated returns (bytes32) {
        return SECURITY_PROXY_IMPLEMENTATION_SLOT;
    }

    /**
     * @notice Avoiding collision with the actual logic contract which is the next in the chain.
     * Falls back to the TransparentUpgradeableProxy.upgradeToAndCall() function of the next contract.
     * @inheritdoc UUPSUpgradeable
     */
    function upgradeToAndCall(address, bytes memory) public payable override onlyProxy {
        _fallback();
    }

    /**
     * @notice Avoiding collision with the actual logic contract which is the next in the chain.
     * Falls back to UUPSUpgradeable.upgradeToAndCall().
     */
    function upgradeSecurityProxyAndCall(address newImplementation, bytes memory data)
        public
        payable
        onlyProxy
        onlySecurityProxyAdmin
    {
        super.upgradeToAndCall(newImplementation, data);
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
    function getCheckpointThreshold(string memory funcSig) public view onlySecurityProxyAdmin returns (uint256) {
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

    /// @inheritdoc UUPSUpgradeable
    function _authorizeUpgrade(address) internal view override {
        require(msg.sender == _getStorage().admin);
    }

    /// @inheritdoc Proxy
    function _implementation() internal view override returns (address) {
        return StorageSlot.getAddressSlot(SECURITY_PROXY_IMPLEMENTATION_SLOT).value;
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

    function _getStorage() internal view returns (Storage storage $) {
        assembly {
            $.slot := SECURITY_PROXY_STORAGE_SLOT
        }
    }

    receive() external payable {}
}
