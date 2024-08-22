// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @dev All role ids are keccak256() of their names.
bytes32 constant FIREWALL_ADMIN_ROLE = 0x98e851166691f2754ebd45a95aded8e2022948d80311058644ab62dcc95eddca;
bytes32 constant PROTOCOL_ADMIN_ROLE = 0xd0c934f24ef5a377dc3832429ce607cbe940a3ca3c6cd7e532bd35b4b212d196;
bytes32 constant CHECKPOINT_MANAGER_ROLE = 0x2744166e218551d4b70cd805a1125548316250adef86b0e4941caa239677a49c;
bytes32 constant LOGIC_UPGRADER_ROLE = 0x8cd1a30abbcda9a4b45f36d916f90dd3359477439ecac772ba02d299a01d78cb;
bytes32 constant CHECKPOINT_EXECUTOR_ROLE = 0xae57c28fd3eb1dad9c6bc61e0a47e0f57230389fedc20e0381b101467bc4b075;

interface IFirewallAccess {
    function isFirewallAdmin(address caller) external view returns (bool);
    function isProtocolAdmin(address caller) external view returns (bool);
    function isCheckpointManager(address caller) external view returns (bool);
    function isLogicUpgrader(address caller) external view returns (bool);
    function isCheckpointExecutor(address caller) external view returns (bool);
}

contract FirewallAccess is AccessControl, IFirewallAccess {
    constructor(address _defaultAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, _defaultAdmin);
        _setRoleAdmin(PROTOCOL_ADMIN_ROLE, FIREWALL_ADMIN_ROLE);
        _setRoleAdmin(CHECKPOINT_MANAGER_ROLE, PROTOCOL_ADMIN_ROLE);
        _setRoleAdmin(LOGIC_UPGRADER_ROLE, PROTOCOL_ADMIN_ROLE);
        _setRoleAdmin(CHECKPOINT_EXECUTOR_ROLE, PROTOCOL_ADMIN_ROLE);
    }

    function isFirewallAdmin(address caller) public view returns (bool) {
        return hasRole(FIREWALL_ADMIN_ROLE, caller);
    }

    function isProtocolAdmin(address caller) public view returns (bool) {
        return hasRole(PROTOCOL_ADMIN_ROLE, caller);
    }

    function isCheckpointManager(address caller) public view returns (bool) {
        return hasRole(PROTOCOL_ADMIN_ROLE, caller) || hasRole(CHECKPOINT_MANAGER_ROLE, caller);
    }

    function isLogicUpgrader(address caller) public view returns (bool) {
        return hasRole(PROTOCOL_ADMIN_ROLE, caller) || hasRole(LOGIC_UPGRADER_ROLE, caller);
    }

    function isCheckpointExecutor(address caller) public view returns (bool) {
        return hasRole(PROTOCOL_ADMIN_ROLE, caller) || hasRole(CHECKPOINT_EXECUTOR_ROLE, caller);
    }
}
