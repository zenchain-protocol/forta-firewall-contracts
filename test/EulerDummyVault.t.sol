// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "evc/interfaces/IEthereumVaultConnector.sol";
import "evc/EthereumVaultConnector.sol";
import "../src/euler/EulerAttestationHelper.sol";
import "../src/euler/DummyVault.sol";
import {ISecurityPolicy, SecurityPolicy} from "../src/SecurityPolicy.sol";
import {Attestation, SecurityValidator} from "../src/SecurityValidator.sol";

contract EulerDummyVaultTest is Test {
    uint256 attesterPrivateKey;
    address attester;
	uint256 userPrivateKey;
    address user;

    SecurityValidator validator;
    SecurityPolicy policy;
    IEVC evc;
    EulerAttestationHelper helper;
    DummyVault vault;

    Attestation attestation;
    bytes attestationSignature;

    function setUp() public {
        attesterPrivateKey = vm.parseUint("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        attester = vm.addr(attesterPrivateKey);
		userPrivateKey = uint256(keccak256("user"));
        user = vm.addr(userPrivateKey);

        validator = new SecurityValidator();
        policy = new SecurityPolicy(validator, attester);
        evc = new EthereumVaultConnector();
        helper = new EulerAttestationHelper();
        vault = new DummyVault(ISecurityPolicy(address(policy)));

        attestation.attester = attester;
        attestation.timeout = 1000000000; // very large - in seconds
        attestation.entryHash = keccak256(
			abi.encode(
				user, // tx.origin
				evc   // msg.sender
			)
		);

        bytes32 checkpointHash1 = policy.checkpointHashOf(DoFirstCheckpoint, address(vault));
        bytes32 checkpointHash2 = policy.checkpointHashOf(DoSecondCheckpoint, address(vault));
        bytes32 executionHash1 = keccak256(abi.encode(checkpointHash1, address(policy), attestation.entryHash));
        bytes32 executionHash2 = keccak256(abi.encode(checkpointHash2, address(policy), executionHash1));
        attestation.exitHash = executionHash2;
        attestation.validator = address(validator);

        // Let the validator schedule the final validation call by calling a helper specified
        // in the attestation.
        attestation.calls.push(abi.encodeWithSelector(helper.scheduleAttestationValidation.selector, address(evc)));
        attestation.recipients.push(address(helper));

        bytes32 hashOfAttestation = validator.hashAttestation(attestation);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPrivateKey, hashOfAttestation);
        attestationSignature = abi.encodePacked(r, s, v);
    }

    function test_attestedEVCBatch() public {
        IEVC.BatchItem[] memory batch = new IEVC.BatchItem[](3);

        // Save the attestation first.
        batch[0] = IEVC.BatchItem({
            targetContract: address(validator),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(SecurityValidator.saveAttestation.selector, attestation, attestationSignature)
        });

        // Call the first vault function.
        batch[1] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doFirst.selector, 123)
        });

        // Call the second vault function.
        batch[2] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doSecond.selector, 456)
        });

        vm.broadcast(userPrivateKey);
        evc.batch(batch);
    }

	function test_attestedEVCBatch_invalid() public {
        IEVC.BatchItem[] memory batch = new IEVC.BatchItem[](2);

        // Save the attestation first.
        batch[0] = IEVC.BatchItem({
            targetContract: address(validator),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(SecurityValidator.saveAttestation.selector, attestation, attestationSignature)
        });

        // Call the second vault function only.
        batch[1] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doSecond.selector, 456)
        });

        vm.broadcast(userPrivateKey);
		vm.expectRevert(abi.encodeWithSelector(SecurityValidator.ExitHashMismatch.selector));
        evc.batch(batch);
    }
}
