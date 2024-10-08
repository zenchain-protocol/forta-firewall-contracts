// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {IFirewallAccess} from "./FirewallAccess.sol";

/**
 * @notice Simplifies interactions with a firewall access contract.
 */
abstract contract FirewallPermissions {
    struct FirewallPermissionsStorage {
        IFirewallAccess firewallAccess;
    }

    /// @custom:storage-location erc7201:forta.FirewallPermissions.storage
    bytes32 private constant STORAGE_SLOT = 0x5a36dfc2750cc10abe5f95f24b6fce874396e21527ff7f50fb33b5ccc8b7d500;

    modifier onlyFirewallAdmin() {
        require(_getFirewallPermissionsStorage().firewallAccess.isFirewallAdmin(msg.sender));
        _;
    }

    modifier onlyCheckpointManager() {
        require(_getFirewallPermissionsStorage().firewallAccess.isCheckpointManager(msg.sender));
        _;
    }

    modifier onlyLogicUpgrader() {
        require(_getFirewallPermissionsStorage().firewallAccess.isLogicUpgrader(msg.sender));
        _;
    }

    modifier onlyCheckpointExecutor() {
        require(_getFirewallPermissionsStorage().firewallAccess.isCheckpointExecutor(msg.sender));
        _;
    }

    function _updateFirewallAccess(IFirewallAccess firewallAccess) internal {
        require(address(firewallAccess) != address(0), "new firewall access contract cannot be zero address");
        _getFirewallPermissionsStorage().firewallAccess = firewallAccess;
    }

    function _getFirewallAccess() internal view returns (IFirewallAccess) {
        return _getFirewallPermissionsStorage().firewallAccess;
    }

    function _getFirewallPermissionsStorage() private pure returns (FirewallPermissionsStorage storage $) {
        assembly {
            $.slot := STORAGE_SLOT
        }
    }

    function _isTrustedAttester(address attester) internal view returns (bool) {
        return _getFirewallPermissionsStorage().firewallAccess.isTrustedAttester(attester);
    }
}
