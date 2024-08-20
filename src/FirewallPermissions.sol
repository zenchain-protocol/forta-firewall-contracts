// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {IFirewallAccess} from "./FirewallAccess.sol";

abstract contract FirewallPermissions {
    struct FirewallPermissionsStorage {
        IFirewallAccess firewallAccess;
    }

    /// @custom:storage-location erc7201:forta.FirewallPermissions.storage
    bytes32 private constant STORAGE_SLOT = 0x5a36dfc2750cc10abe5f95f24b6fce874396e21527ff7f50fb33b5ccc8b7d500;

    modifier onlySecurityAdmin() {
        require(_getFirewallPerimissionsStorage().firewallAccess.isFirewallAdmin(msg.sender));
        _;
    }

    modifier onlyCheckpointManager() {
        require(_getFirewallPerimissionsStorage().firewallAccess.isCheckpointManager(msg.sender));
        _;
    }

    modifier onlyLogicUpgrader() {
        require(_getFirewallPerimissionsStorage().firewallAccess.isLogicUpgrader(msg.sender));
        _;
    }

    function _updateFirewallAccess(IFirewallAccess firewallAccess) internal {
        _getFirewallPerimissionsStorage().firewallAccess = firewallAccess;
    }

    function _getFirewallAccess() internal view returns (IFirewallAccess) {
        return _getFirewallPerimissionsStorage().firewallAccess;
    }

    function _getFirewallPerimissionsStorage() private pure returns (FirewallPermissionsStorage storage $) {
        assembly {
            $.slot := STORAGE_SLOT
        }
    }
}
