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
    uint256 otherUserPrivateKey;
    address otherUser;

    SecurityValidator validator;
    SecurityPolicy policy;
    IEVC evc;
    EulerAttestationHelper helper;
    DummyVault vault;

    Attestation attestation;
    bytes attestationSignature;

    bytes32 checkpointHash1;
    bytes32 checkpointHash2;

    function setUp() public {
        attesterPrivateKey = vm.parseUint("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        attester = vm.addr(attesterPrivateKey);
        userPrivateKey = uint256(keccak256("user"));
        user = vm.addr(userPrivateKey);
        otherUserPrivateKey = uint256(keccak256("otherUser"));
        otherUser = vm.addr(otherUserPrivateKey);

        validator = new SecurityValidator();
        policy = new SecurityPolicy(validator, attester);
        evc = new EthereumVaultConnector();
        helper = new EulerAttestationHelper();
        vault = new DummyVault(ISecurityPolicy(address(policy)));

        attestation.attester = attester;
        attestation.timeout = 1000000000; // very large - in seconds
        attestation.entryHash = bytes32(uint256(1));
        attestation.enter = true;

        _computeAttestationHashes(address(policy));

        // Let the validator schedule the final validation call by calling a helper specified
        // in the attestation.
        attestation.calls.push(abi.encodeWithSelector(helper.scheduleAttestationValidation.selector, address(evc)));
        attestation.recipients.push(address(helper));

        _signAttestation();
    }

    function _computeAttestationHashes(address caller) public {
        checkpointHash1 = policy.checkpointHashOf(DoFirstCheckpoint, address(vault));
        checkpointHash2 = policy.checkpointHashOf(DoSecondCheckpoint, address(vault));
        bytes32 executionHash1 = keccak256(abi.encode(checkpointHash1, caller, attestation.entryHash));
        bytes32 executionHash2 = keccak256(abi.encode(checkpointHash2, caller, executionHash1));
        attestation.exitHash = executionHash2;
        attestation.validator = address(validator);
    }

    function _signAttestation() internal {
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

    function test_attestedEVCBatch_exitHashMismatch() public {
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

    function test_attestationGas() public {
        attestation.entryHash = bytes32(uint256(1));
        attestation.calls = new bytes[](0);
        attestation.recipients = new address[](0);
        _computeAttestationHashes(user);
        _signAttestation();

        vm.startPrank(user, user);

        uint256 startGasLeft = gasleft();
        uint256 prevGasLeft = startGasLeft;

        validator.saveAttestation(attestation, attestationSignature);
        console.log("saveAttestation():", prevGasLeft - gasleft());
        prevGasLeft = gasleft();

        validator.executeCheckpoint(checkpointHash1);
        console.log("executeCheckpoint(1):", prevGasLeft - gasleft());
        prevGasLeft = gasleft();

        validator.executeCheckpoint(checkpointHash2);
        console.log("executeCheckpoint(2):", prevGasLeft - gasleft());
        prevGasLeft = gasleft();

        validator.exitAttestedCall();
        console.log("exitAttestedCall():", prevGasLeft - gasleft());
        prevGasLeft = gasleft();

        console.log("total:", startGasLeft - prevGasLeft);

        vm.stopPrank();
    }
}
