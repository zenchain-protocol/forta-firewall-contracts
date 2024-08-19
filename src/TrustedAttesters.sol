// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

interface ITrustedAttesters {
    function isTrustedAttester(address attester) external view returns (bool);
    function addAttesters(address[] calldata added) external;
    function removeAttesters(address[] calldata removed) external;
}

bytes32 constant ATTESTER_MANAGER_ROLE = keccak256("ATTESTER_MANAGER_ROLE");

contract TrustedAttesters is AccessControl {
    mapping(address => bool) attesters;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ATTESTER_MANAGER_ROLE, msg.sender);
    }

    function isTrustedAttester(address attester) public view returns (bool) {
        return attesters[attester];
    }

    function addAttesters(address[] calldata added) public onlyRole(ATTESTER_MANAGER_ROLE) {
        for (uint256 i = 0; i < added.length; i++) {
            attesters[added[i]] = true;
        }
    }

    function removeAttesters(address[] calldata removed) public onlyRole(ATTESTER_MANAGER_ROLE) {
        for (uint256 i = 0; i < removed.length; i++) {
            delete(attesters[removed[i]]);
        }
    }
}
