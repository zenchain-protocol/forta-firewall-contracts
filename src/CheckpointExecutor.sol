// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import {IExternalFirewall} from "./ExternalFirewall.sol";

/**
 * @notice A helper contract to call an external firewall.
 */
abstract contract CheckpointExecutor {
    using StorageSlot for bytes32;

    struct CheckpointExecutorStorage {
        IExternalFirewall externalFirewall;
    }

    /// @custom:storage-location erc7201:forta.CheckpointExecutor.storage
    bytes32 private constant STORAGE_SLOT = 0x056e02eadf378bb204991810c69f5fd30d0c5daa999b3432711954755cff9a00;

    function _executeCheckpoint(bytes4 selector, uint256 ref) internal virtual {
        CheckpointExecutorStorage storage $;
        assembly {
            $.slot := STORAGE_SLOT
        }
        IExternalFirewall($.externalFirewall).executeCheckpoint(selector, ref);
    }
}
