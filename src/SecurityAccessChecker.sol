// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {ISecurityAccess} from "./SecurityAccessControl.sol";

abstract contract SecurityAccessChecker {
    struct SecurityAccessCheckerStorage {
        ISecurityAccess securityAccess;
    }

    /// @custom:storage-location erc7201:forta.SecurityAccessChecker.storage
    bytes32 private constant STORAGE_SLOT = 0x10ea73a98ef36848ebf543b33d56d56c178a2126067fff78fb1481da939b4500;

    modifier onlySecurityAdmin() {
        require(_getSecurityAccessCheckerStorage().securityAccess.isSecurityAdmin(msg.sender));
        _;
    }

    modifier onlyCheckpointManager() {
        require(_getSecurityAccessCheckerStorage().securityAccess.isCheckpointManager(msg.sender));
        _;
    }

    modifier onlyLogicUpgrader() {
        require(_getSecurityAccessCheckerStorage().securityAccess.isLogicUpgrader(msg.sender));
        _;
    }

    function _updateSecurityAccess(ISecurityAccess securityAccess) internal {
        _getSecurityAccessCheckerStorage().securityAccess = securityAccess;
    }

    function _getSecurityAccess() internal view returns (ISecurityAccess) {
        return _getSecurityAccessCheckerStorage().securityAccess;
    }

    function _getSecurityAccessCheckerStorage() private pure returns (SecurityAccessCheckerStorage storage $) {
        assembly {
            $.slot := STORAGE_SLOT
        }
    }
}
