// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/proxy/Proxy.sol";

interface ISecurityProxy {
    function setImplementation(address newImplementation) external;
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

    /// @notice Implements the _implementation() function of the proxy.
    function _implementation() internal view override returns (address) {
        return implementation;
    }

    function _fallback() internal override {
        uint256 threshold = thresholds[msg.sig];
        if (threshold > 1) {
            /// TODO: Check here thresholds and execute checkpoint before falling back
            /// to the logic contract!!! That helps having automatic checkpoints for
            /// any function in the logic contract.
        }
        super._fallback();
    }

    /// TODO: Use the access control library.
    function setImplementation(address newImplementation) public {
        implementation = newImplementation;
    }

    /// TODO: Use the access control library.
    function setCheckpointThreshold(string memory funcSig, uint256 threshold) public {
        thresholds[bytes4(keccak256(abi.encode(funcSig)))] = threshold;
    }

    /// TODO: Use the access control library.
    function getCheckpointThreshold(string memory funcSig) public view returns (uint256) {
        return thresholds[bytes4(keccak256(abi.encode(funcSig)))];
    }

    receive() external payable {}
}
