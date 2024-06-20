// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console, Vm} from "forge-std/Test.sol";
import "evc/interfaces/IEthereumVaultConnector.sol";
import "evc/EthereumVaultConnector.sol";
import "../src/euler/DummyVault.sol";
import {ISecurityPolicy, SecurityPolicy} from "../src/SecurityPolicy.sol";
import {Attestation, ISecurityValidator, SecurityValidator, BYPASS_FLAG} from "../src/SecurityValidator.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

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
        policy = new SecurityPolicy(ISecurityValidator(address(validator)), attester);
        evc = new EthereumVaultConnector();
        vault = new DummyVault(ISecurityPolicy(address(policy)));

        attestation.timeout = 1000000000; // very large - in seconds

        _computeAttestationHashes(address(policy));
        _signAttestation();
    }

    function _computeAttestationHashes(address caller) public {
        bytes memory call1 = abi.encodeWithSignature("doFirst(uint256)", 123);
        bytes32 callHash1 = keccak256(abi.encode(address(evc), call1));
        bytes32 checkpointHash1 = policy.checkpointHashOf(DoFirstCheckpoint, callHash1, address(vault));
        executionHash1 = validator.executionHashFrom(checkpointHash1, caller, bytes32(uint256(0)));

        bytes memory call2 = abi.encodeWithSignature("doSecond(uint256)", 456);
        bytes32 callHash2 = keccak256(abi.encode(address(evc), call2));
        bytes32 checkpointHash2 = policy.checkpointHashOf(DoSecondCheckpoint, callHash2, address(vault));
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

    function test_debugValidation() public {
        IEVC.BatchItem[] memory batch = new IEVC.BatchItem[](2);

        // Skip attestation.

        // Call the first vault function.
        batch[0] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doFirst.selector, 123)
        });

        // Call the second vault function.
        batch[1] = IEVC.BatchItem({
            targetContract: address(vault),
            onBehalfOfAccount: user,
            value: 0,
            data: abi.encodeWithSelector(DummyVault.doSecond.selector, 456)
        });

        // Avoid revert without attestation by using the bypass flag
        // and capture the values from the log.
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
        assertEq(bytes32(0xa7247c959f5cdf3cd7ddcd7d678a3144ee7b4f7aa990a89fffea48521b48e391), foundHash);
    }

    function test_validationFailure() public {
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
        bytes32 expectedHash = 0x977bc7e7db2e3b4a8c0c1429b918361dd3088df77fc5e376845e935419067de1;
        bytes32 computedHash = 0x717422506f33fe9a54df6f78e07e37b48c4f1bdc0616c68107571d74488a5a01;
        vm.expectRevert(
            abi.encodeWithSelector(
                SecurityValidator.InvalidExecutionHash.selector,
                address(validator),
                expectedHash,
                computedHash
            )
        );
        evc.batch(batch);
    }

    function test_attestationGas() public {
        _computeAttestationHashes(address(policy));
        _signAttestation();

        vm.startPrank(address(evc), user);

        uint256 startGasLeft = gasleft();
        uint256 prevGasLeft = startGasLeft;

        validator.saveAttestation(attestation, attestationSignature);
        console.log("saveAttestation():", prevGasLeft - gasleft());
        prevGasLeft = gasleft();

        vault.doFirst(123);
        console.log("doFirst(123):", prevGasLeft - gasleft());
        prevGasLeft = gasleft();

        vault.doSecond(456);
        console.log("doSecond(456):", prevGasLeft - gasleft());
        prevGasLeft = gasleft();

        console.log("total:", startGasLeft - prevGasLeft);

        vm.stopPrank();
    }
}
