// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "evc/interfaces/IVault.sol";
import {ISecurityPolicy, Threshold} from "../SecurityPolicy.sol";

bytes32 constant DoFirstCheckpoint = keccak256("doFirst");
bytes32 constant DoSecondCheckpoint = keccak256("doSecond");

contract DummyVault is IVault {
    ISecurityPolicy policyContract;

    constructor(ISecurityPolicy _policyContract) {
        policyContract = _policyContract;
    }

    function disableController() public {
        // no-op
    }

    function checkAccountStatus(address, address[] calldata) public pure returns (bytes4 magicValue) {
        return 0xb168c58f;
    }

    function checkVaultStatus() public pure returns (bytes4 magicValue) {
        return 0x4b3d1223;
    }

    function doFirst(uint256 amount) public {
        policyContract.executeCheckpoint(DoFirstCheckpoint, amount, Threshold.Accumulated);
    }

    function doSecond(uint256 amount) public {
        policyContract.executeCheckpoint(DoSecondCheckpoint, amount, Threshold.Accumulated);
    }
}
