// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console, Vm} from "forge-std/Test.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IEVC, EthereumVaultConnector} from "evc/EthereumVaultConnector.sol";
import "./helpers/DummyVault.sol";
import {Attestation, ISecurityValidator, SecurityValidator, BYPASS_FLAG} from "../src/SecurityValidator.sol";
import {Sensitivity} from "../src/Sensitivity.sol";

contract EVCTest is Test {
    using Sensitivity for uint256;

    uint256 attesterPrivateKey;
    address attester;
    uint256 userPrivateKey;
    address user;
    uint256 otherUserPrivateKey;
    address otherUser;

    SecurityValidator validator;
    IEVC evc;
    DummyVault vault;

    Attestation attestation;
    bytes attestationSignature;

    bytes32 executionHash1;
    bytes32 executionHash2;

    function setUp() public {
        attesterPrivateKey = vm.parseUint("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        attester = vm.addr(attesterPrivateKey);
        userPrivateKey = uint256(keccak256("user"));
        user = vm.addr(userPrivateKey);
        otherUserPrivateKey = uint256(keccak256("otherUser"));
        otherUser = vm.addr(otherUserPrivateKey);

        validator = new SecurityValidator();
        evc = new EthereumVaultConnector();
        vault = new DummyVault(ISecurityValidator(address(validator)));

        /// very large - in seconds
        attestation.deadline = 1000000000;

        _computeAttestationHashes(address(vault));
        _signAttestation();
    }

    function _computeAttestationHashes(address caller) public {
        uint256 ref1 = 123;
        bytes32 checkpointHash1 =
            keccak256(abi.encode(address(evc), address(vault), DummyVault.doFirst.selector, ref1.reduceSensitivity()));
        executionHash1 = validator.executionHashFrom(checkpointHash1, caller, bytes32(uint256(0)));

        uint256 ref2 = 456;
        bytes32 checkpointHash2 =
            keccak256(abi.encode(address(evc), address(vault), DummyVault.doSecond.selector, ref2.reduceSensitivity()));
        executionHash2 = validator.executionHashFrom(checkpointHash2, caller, executionHash1);

        attestation.executionHashes = new bytes32[](2);
        attestation.executionHashes[0] = executionHash1;
        attestation.executionHashes[1] = executionHash2;
    }

    function _signAttestation() internal {
        bytes32 hashOfAttestation = validator.hashAttestation(attestation);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPrivateKey, hashOfAttestation);
        attestationSignature = abi.encodePacked(r, s, v);
    }

    function test_attestedEVCBatch() public {
        IEVC.BatchItem[] memory batch = new IEVC.BatchItem[](3);

        /// Save the attestation first.
        batch[0] = IEVC.BatchItem({
            targetContract: address(validator),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(SecurityValidator.saveAttestation.selector, attestation, attestationSignature)
        });

        /// Call the first vault function.
        batch[1] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doFirst.selector, 123)
        });

        /// Call the second vault function.
        batch[2] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doSecond.selector, 456)
        });

        vm.broadcast(userPrivateKey);
        evc.batch(batch);
    }

    function test_attestedEVCBatch_twoTx() public {
        vm.broadcast(userPrivateKey);
        /// Store the attestation in the first transaction.
        validator.storeAttestation(attestation, attestationSignature);

        IEVC.BatchItem[] memory batch = new IEVC.BatchItem[](2);

        /// Exclude the attestation from the batch.

        /// Call the first vault function.
        batch[0] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doFirst.selector, 123)
        });

        /// Call the second vault function.
        batch[1] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doSecond.selector, 456)
        });

        /// Send the batch - it should be able to use the attestation from the first tx.
        vm.broadcast(userPrivateKey);
        evc.batch(batch);

        /// The second try should fail as there are no attestations anymore.
        vm.expectRevert();
        evc.batch(batch);
    }

    function test_debugValidation() public {
        IEVC.BatchItem[] memory batch = new IEVC.BatchItem[](2);

        /// Skip attestation.

        /// Call the first vault function.
        batch[0] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doFirst.selector, 123)
        });

        /// Call the second vault function.
        batch[1] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doSecond.selector, 456)
        });

        /// Avoid revert without attestation by using the bypass flag
        /// and capture the values from the log.
        vm.etch(BYPASS_FLAG, bytes("1"));
        vm.recordLogs();
        vm.broadcast(userPrivateKey);
        evc.batch(batch);

        bytes32 eventHash = keccak256("CheckpointExecuted(address,bytes32)");
        Vm.Log[] memory entries = vm.getRecordedLogs();
        assertGt(entries.length, 0);
        address foundValidator;
        bytes32 foundHash;
        for (uint256 i = 0; i < entries.length; i++) {
            Vm.Log memory entry = entries[i];
            if (entry.topics[0] != eventHash) {
                continue;
            }
            (foundValidator, foundHash) = abi.decode(entry.data, (address, bytes32));
        }
        assertEq(address(validator), foundValidator);
        assertEq(bytes32(0xddcbe8ad5fe670c376b05886934bc334946c7f3171c1397504444f18bd2c9cf0), foundHash);
    }

    function test_validationFailure() public {
        IEVC.BatchItem[] memory batch = new IEVC.BatchItem[](2);

        /// Save the attestation first.
        batch[0] = IEVC.BatchItem({
            targetContract: address(validator),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(SecurityValidator.saveAttestation.selector, attestation, attestationSignature)
        });

        /// Call the second vault function only.
        batch[1] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doSecond.selector, 456)
        });

        vm.broadcast(userPrivateKey);
        bytes32 expectedHash = 0x8eef2e46cd1e7ae75ac414283c677c544c34901ed90ce97905ebb9b4a87052b3;
        bytes32 computedHash = 0x70c96fd7e5f694964fb6a6921e5d572ef997cd3cb3257ff901a4651e2242d0cc;
        vm.expectRevert(
            abi.encodeWithSelector(
                SecurityValidator.InvalidExecutionHash.selector, address(validator), expectedHash, computedHash
            )
        );
        evc.batch(batch);
    }

    function test_attestationGas_saveAttestation() public {
        _computeAttestationHashes(address(vault));
        _signAttestation();

        vm.startPrank(address(evc), user);
        validator.saveAttestation(attestation, attestationSignature);
        vault.doFirst(123);
        vault.doSecond(456);

        vm.stopPrank();
    }

    function test_attestationGas_storeAttestation() public {
        _computeAttestationHashes(address(vault));
        _signAttestation();

        vm.startPrank(address(evc), user);
        validator.storeAttestation(attestation, attestationSignature);

        vm.stopPrank();
    }
}
