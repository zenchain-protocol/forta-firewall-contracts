// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "evc/interfaces/IVault.sol";
import {Checkpoint, ACTIVATION_ALWAYS_ACTIVE} from "../../src/SecurityLogic.sol";
import {SecurityPolicy} from "../../src/SecurityPolicy.sol";
import {ISecurityValidator} from "../../src/SecurityValidator.sol";
import {ISecurityAccess} from "../../src/SecurityAccessControl.sol";
import {ITrustedAttesters} from "../../src/TrustedAttesters.sol";

bytes32 constant DoFirstCheckpoint = keccak256("doFirst");
bytes32 constant DoSecondCheckpoint = keccak256("doSecond");

contract DummyTrustedAttesters {
    function isTrustedAttester(address) public pure returns (bool) {
        return true;
    }

    function addAttesters(address[] calldata added) public {}

    function removeAttesters(address[] calldata removed) public {}
}

contract DummySecurityAccess {
    function isSecurityAdmin(address) public pure returns (bool) {
        return true;
    }

    function isCheckpointManager(address) external pure returns (bool) {
        return true;
    }

    function isLogicUpgrader(address) external pure returns (bool) {
        return true;
    }
}

contract DummyVault is IVault, SecurityPolicy {
    constructor(ISecurityValidator _validator)
        SecurityPolicy(_validator, _initTrustedAttesters(), bytes32(0), _initSecurityAccess())
    {
        Checkpoint memory checkpoint;
        checkpoint.threshold = 0;
        checkpoint.refStart = 4;
        checkpoint.refEnd = 36;
        checkpoint.activation = ACTIVATION_ALWAYS_ACTIVE;
        checkpoint.trustedOrigin = 0;
        setCheckpoint("doFirst(uint256)", checkpoint);
        setCheckpoint("doSecond(uint256)", checkpoint);
    }

    function _initTrustedAttesters() private returns (ITrustedAttesters) {
        return ITrustedAttesters(address(new DummyTrustedAttesters()));
    }

    function _initSecurityAccess() private returns (ISecurityAccess) {
        return ISecurityAccess(address(new DummySecurityAccess()));
    }

    function disableController() public {}

    function checkAccountStatus(address, address[] calldata) public pure returns (bytes4 magicValue) {
        return 0xb168c58f;
    }

    function checkVaultStatus() public pure returns (bytes4 magicValue) {
        return 0x4b3d1223;
    }

    function doFirst(uint256 amount) public {
        _secureExecution(amount);
    }

    function doSecond(uint256 amount) public {
        _secureExecution(amount);
    }
}
