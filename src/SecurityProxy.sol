// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/proxy/Proxy.sol";
import {ISecurityValidator} from "./SecurityValidator.sol";

interface ISecurityProxy {
    function setNextImplementation(address newImplementation) external;
    function setSecurityValidator(ISecurityValidator _validator) external;
    function setCheckpointThreshold(string memory funcSig, uint256 threshold) external;
    function getCheckpointThreshold(string memory funcSig) external view returns (uint256);
}

/**
 * @title Security proxy middleware
 * @notice This should act as the logic contract a proxy points to. The security proxy
 * has functions to mutate the storage of the original proxy. It either does that or
 * falls back to the actual logic implementation.
 * Proxy (DELEGATECALL)-> SecurityProxy (DELEGATECALL)-> Logic
 * The security proxy does not fallback to the logic if it prefers to instead write something
 * to the storage of the Proxy (like the actual logic implementation address or the thresholds).
 */
contract SecurityProxy is Proxy {
    /// keccak256("forta.proxy") - 1
    /// Skipping the part of storage that could likely create collision in the original proxy.
    /// TODO: Instead, use namespaced storage slot for a struct that holds all storage.
    uint256[0xb194c6016d78b6a952fbefc94316b0e8122b922095a36f35409d2767c3612b32] private __gap;

    mapping(bytes4 => uint256) thresholds;

    /// @notice The actual fallback logic address that executes business logic.
    address implementation;

    /// @notice The validator contract that takes the checkpoint execution call.
    ISecurityValidator validator;

    /// @notice Implements the _implementation() function of the proxy.
    function _implementation() internal view override returns (address) {
        return implementation;
    }

    function _fallback() internal override {
        (uint256 ref, bool ok) = thresholdActivated();
        if (ok) {
            validator.executeCheckpoint(keccak256(abi.encode(msg.sender, address(this), msg.sig, ref)));
        }
        super._fallback();
    }

    /// TODO: Use the access control library.
    function setNextImplementation(address newImplementation) public {
        implementation = newImplementation;
    }

    /// TODO: Use the access control library.
    function setSecurityValidator(ISecurityValidator _validator) public {
        validator = _validator;
    }

    /// TODO: Use the access control library.
    function setCheckpointThreshold(string memory funcSig, uint256 threshold) public {
        thresholds[bytes4(keccak256(bytes(funcSig)))] = threshold;
    }

    /// TODO: Use the access control library.
    function getCheckpointThreshold(string memory funcSig) public view returns (uint256) {
        return thresholds[bytes4(keccak256(bytes(funcSig)))];
    }

    /// TODO: This should be able to read other arguments.
    function thresholdActivated() internal view returns (uint256, bool) {
        uint256 threshold = thresholds[msg.sig];
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
        return (scaleDownRef(ref), true);
    }

    /// TODO: Use log1.01 here or similar.
    function scaleDownRef(uint256 ref) internal pure returns (uint256) {
        return ref;
    }

    receive() external payable {}
}
