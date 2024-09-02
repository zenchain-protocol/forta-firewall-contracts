// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {IFirewall, Firewall} from "./Firewall.sol";
import {ISecurityValidator, Attestation} from "./SecurityValidator.sol";
import {IFirewallAccess} from "./FirewallAccess.sol";

interface IProxyFirewall is IFirewall {
    function initializeFirewallConfig(
        ISecurityValidator _validator,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) external;

    function upgradeNextAndCall(address newImplementation, bytes memory data) external payable;
}

/**
 * @notice This contract provides firewall functionality as an intermediary contract
 * between a proxy and a logic contract, acting as a proxy firewall. It automatically
 * intercepts any calls to the logic contract, tries to execute checkpoints if needed and
 * falls back to the original logic contract with delegatecall.
 *
 * The storage used by the Firewall contract and the proxy firewall contract is namespaced
 * and causes no collision. The checkpoints must be adjusted by calling the setCheckpoint(Checkpoint)
 * function.
 *
 * When used with an ERC1967 proxy and a UUPSUpgradeable logic contract, the proxy storage points
 * points to the proxy firewall and the proxy firewall points to the logic contract, in the proxy
 * storage. Both of the proxy firewall and the logic contract operate on the proxy storage.
 *
 * The UUPSUpgradeable logic contract keeps the privileges to modify the implementation specified
 * at ERC1967 proxy storage. The proxy firewall is able to point to a next implementation on the
 * proxy storage. To upgrade to the proxy firewall atomically, the logic contract should be invoked
 * to modify the implementation storage on the proxy, in order to point to the proxy firewall logic.
 * As a next action in the same transaction, the proxy firewall should be pointed to the logic contract.
 * For such upgrade cases, upgradeToAndCall() and upgradeNextAndCall() functions are made available
 * from the proxy firewall and the UUPSUpgradeable contracts, respectively.
 *
 * This contract preserves msg.sender, msg.sig and msg.data because it falls back to doing a DELEGATECALL
 * on the next implementation with the same call data.
 */
contract ProxyFirewall is IProxyFirewall, Firewall, Proxy, Multicall {
    error UpgradeNonPayable();

    /// @custom:storage-location erc7201:forta.ProxyFirewall.next.implementation
    bytes32 internal constant NEXT_IMPLEMENTATION_SLOT =
        0x9e3fe722f43dfec528e68fcd2db9596358ca7182739c61c40dd16fd5eb878300;

    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the security config for the first time.
     * @param _validator Validator used for checkpoint execution calls.
     * @param _attesterControllerId The ID of the external controller which keeps settings related
     * to the attesters.
     * @param _firewallAccess Firewall access controller.
     */
    function initializeFirewallConfig(
        ISecurityValidator _validator,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) public initializer {
        _updateFirewallConfig(_validator, _attesterControllerId, _firewallAccess);
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
