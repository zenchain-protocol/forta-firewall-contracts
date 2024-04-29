// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {SecurityValidator} from "../src/SecurityValidator.sol";

bytes32 constant TEST_CHECKPOINT_1 = keccak256("1");
bytes32 constant TEST_CHECKPOINT_2 = keccak256("2");

contract SecurityValidatorTest is Test {
	uint256 attesterPrivateKey;
    address attester;
	address caller1;
	address caller2;

	SecurityValidator validator;

	bytes32 attestationHash;
	bytes attestationSignature;

	function setUp() public {
		attesterPrivateKey = vm.parseUint("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        attester = vm.addr(attesterPrivateKey);
		caller1 = vm.addr(uint256(keccak256("caller1")));
		caller2 = vm.addr(uint256(keccak256("caller2")));

		validator = new SecurityValidator(attester, false);
		bytes32 approvalHash1 = validator.approvalHashOf(TEST_CHECKPOINT_1, caller1, bytes32(0));
		bytes32 approvalHash2 = validator.approvalHashOf(TEST_CHECKPOINT_2, caller2, approvalHash1);
		attestationHash = approvalHash2;
		(uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPrivateKey, attestationHash);
		attestationSignature = abi.encodePacked(r, s, v);
	}

	function test_attestation() public {
		vm.prank(attester);
		validator.saveAttestation(attestationHash, attestationSignature);

		vm.prank(caller1);
		validator.executeCheckpoint(TEST_CHECKPOINT_1);

		vm.expectRevert();
		validator.validateAttestation();

		vm.prank(caller2);
		validator.executeCheckpoint(TEST_CHECKPOINT_2);

		validator.validateAttestation();
	}
}
