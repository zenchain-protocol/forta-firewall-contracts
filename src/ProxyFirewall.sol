// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {IFirewall, Firewall} from "./Firewall.sol";
import {ISecurityValidator, Attestation} from "./SecurityValidator.sol";
import {ITrustedAttesters} from "./TrustedAttesters.sol";
import {IFirewallAccess} from "./FirewallAccess.sol";

interface IProxyFirewall is IFirewall {
    function initializeSecurityConfig(
        ISecurityValidator _validator,
        ITrustedAttesters _trustedAttesters,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) external;

    function upgradeNextAndCall(address newImplementation, bytes memory data) external payable;
}

contract ProxyFirewall is IProxyFirewall, Firewall, Proxy {
    error UpgradeNonPayable();

    /// @custom:storage-location erc7201:forta.ProxyFirewall.next.implementation
    bytes32 internal constant NEXT_IMPLEMENTATION_SLOT =
        0x9e3fe722f43dfec528e68fcd2db9596358ca7182739c61c40dd16fd5eb878300;

    /**
     * @notice Initializes the security config for the first time.
     * @param _validator The security validator which the proxy firewall calls for saving
     * the attestation and executing checkpoints.
     */
    function initializeSecurityConfig(
        ISecurityValidator _validator,
        ITrustedAttesters _trustedAttesters,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) public initializer {
        _updateSecurityConfig(_validator, _trustedAttesters, _attesterControllerId, _firewallAccess);
    }

    /**
     * @notice Sets the next implementation contract which the fallback function will delegatecall to.
     * Copied and adapted from OpenZeppelin ERC1967Utils.upgradeToAndCall().
     * @param newImplementation The next implementation contract
     * @param data Call data
     */
    function upgradeNextAndCall(address newImplementation, bytes memory data) public payable onlyLogicUpgrader {
        StorageSlot.getAddressSlot(NEXT_IMPLEMENTATION_SLOT).value = newImplementation;
        if (data.length > 0) {
            Address.functionDelegateCall(newImplementation, data);
        } else {
            _checkNonPayable();
        }
    }

    /// @inheritdoc Proxy
    function _implementation() internal view override returns (address) {
        return StorageSlot.getAddressSlot(NEXT_IMPLEMENTATION_SLOT).value;
    }

    /// @inheritdoc Proxy
    function _fallback() internal override {
        _secureExecution();
        super._fallback();
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
