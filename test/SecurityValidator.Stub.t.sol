// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/SecurityValidator.sol";
import "../src/SecurityPolicy.sol";

bytes32 constant CHECKPOINT_ID_1 = keccak256("id1");
bytes32 constant CHECKPOINT_HASH_1 = keccak256("hash1");
bytes32 constant CHECKPOINT_ID_2 = keccak256("id2");
bytes32 constant CHECKPOINT_HASH_2 = keccak256("hash2");

bool constant VALIDATION_IS_DISABLED = true;

// This is for testing that the validator can still keep a happy face
// when the validation and execution is bypassed/disabled and interfacing
// is correct.
contract SecurityValidatorStubTest is Test {
    uint256 attesterPrivateKey;
    address attester;
    address caller1;
    address caller2;

    SecurityValidator validator;
    SecurityPolicy policy;

    SecurityValidator.Attestation attestation;
    bytes attestationSignature;

    function setUp() public {
        attesterPrivateKey = vm.parseUint("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        attester = vm.addr(attesterPrivateKey);
        caller1 = vm.addr(uint256(keccak256("caller1")));
        caller2 = vm.addr(uint256(keccak256("caller2")));

        validator = new SecurityValidator(attester, VALIDATION_IS_DISABLED);
        policy = new SecurityPolicy(validator);

		// use empty attestation
        bytes32 hashOfAttestation = validator.hashAttestation(attestation);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPrivateKey, hashOfAttestation);
        attestationSignature = abi.encodePacked(r, s, v);
    }

    function test_attestation() public {
        vm.prank(attester);
        validator.saveAttestation(attestation, attestationSignature);

        vm.prank(caller1);
        policy.executeCheckpoint(CHECKPOINT_ID_1, CHECKPOINT_HASH_1, 0);

        vm.prank(caller2);
        policy.executeCheckpoint(CHECKPOINT_ID_2, CHECKPOINT_HASH_2, 0);

        validator.validateAttestation();
    }
}
