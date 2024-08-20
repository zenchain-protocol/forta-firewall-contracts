// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console, Vm} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IProxyFirewall, ProxyFirewall} from "../src/ProxyFirewall.sol";
import {Checkpoint, ACTIVATION_CONSTANT_THRESHOLD} from "../src/Firewall.sol";
import {IFirewallAccess, FirewallAccess, FIREWALL_ADMIN_ROLE, PROTOCOL_ADMIN_ROLE} from "../src/FirewallAccess.sol";
import {ITrustedAttesters, TrustedAttesters} from "../src/TrustedAttesters.sol";
import {ISecurityValidator, SecurityValidator, Attestation, BYPASS_FLAG} from "../src/SecurityValidator.sol";
import {Sensitivity} from "../src/Sensitivity.sol";

interface ILogicContract {
    function withdrawAmount(uint256 n) external;
    function getNumber() external view returns (uint256);
}

contract LogicContract {
    uint256 number;

    function withdrawAmount(uint256 n) public {
        number = n;
    }

    function getNumber() public view returns (uint256) {
        return number;
    }
}

contract ProxyFirewallTest is Test {
    using Sensitivity for uint256;

    SecurityValidator validator;
    TrustedAttesters trustedAttesters;
    FirewallAccess firewallAccess;

    ERC1967Proxy mainProxy;
    ProxyFirewall proxyFirewall;
    LogicContract logic;

    ERC1967Proxy altProxy;

    bytes upgradeData;

    Attestation attestation;
    bytes attestationSignature;

    Checkpoint checkpoint;

    function setUp() public {
        validator = new SecurityValidator();

        trustedAttesters = new TrustedAttesters();

        firewallAccess = new FirewallAccess(address(this));

        logic = new LogicContract();

        proxyFirewall = new ProxyFirewall();

        /// Main proxy points to the proxy firewall.
        mainProxy = new ERC1967Proxy(address(proxyFirewall), upgradeData);

        /// Add a trusted attester.
        uint256 attesterPrivateKey = vm.parseUint("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        address attester = vm.addr(attesterPrivateKey);
        address[] memory attesters = new address[](1);
        attesters[0] = attester;
        trustedAttesters.addAttesters(attesters);

        /// Generate an attestation to save later.
        uint256 ref = 234;
        bytes32 checkpointHash = keccak256(
            abi.encode(
                address(this), address(mainProxy), LogicContract.withdrawAmount.selector, ref.reduceSensitivity()
            )
        );
        bytes32 executionHash = validator.executionHashFrom(checkpointHash, address(mainProxy), bytes32(uint256(0)));
        attestation.executionHashes = new bytes32[](1);
        attestation.executionHashes[0] = executionHash;
        attestation.deadline = 1000000000;
        /// very large - in seconds
        bytes32 hashOfAttestation = validator.hashAttestation(attestation);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPrivateKey, hashOfAttestation);
        attestationSignature = abi.encodePacked(r, s, v);

        /// Configure access control.
        firewallAccess.grantRole(FIREWALL_ADMIN_ROLE, address(this));
        firewallAccess.grantRole(PROTOCOL_ADMIN_ROLE, address(this));

        /// Proxy firewall points to the logic contract but that should be on main proxy storage.
        IProxyFirewall(address(mainProxy)).initializeSecurityConfig(
            ISecurityValidator(address(validator)),
            ITrustedAttesters(address(trustedAttesters)),
            bytes32(0),
            IFirewallAccess(firewallAccess)
        );
        IProxyFirewall(address(mainProxy)).upgradeNextAndCall(address(logic), upgradeData);

        /// Keep a default threshold for every test.
        checkpoint.threshold = 123;
        checkpoint.refStart = 4;
        checkpoint.refEnd = 36;
        checkpoint.activation = ACTIVATION_CONSTANT_THRESHOLD;
        checkpoint.trustedOrigin = 0;
        IProxyFirewall(address(mainProxy)).setCheckpoint("withdrawAmount(uint256)", checkpoint);

        /// Define an alternative main proxy that directly integrates with the logic contract.
        altProxy = new ERC1967Proxy(address(logic), upgradeData);
    }

    function testProxyFirewallStorageAccess() public {
        /// Save the attestation first to make the checkpoint work.
        validator.saveAttestation(attestation, attestationSignature);

        vm.startStateDiffRecording();

        /// Let's change the threshold of the proxy firewall but on main proxy storage.
        /// That should work because the implementation of main proxy is the proxy firewall.
        /// So we can treat main proxy as if it's the proxy firewall.
        IProxyFirewall(address(mainProxy)).setCheckpoint("withdrawAmount(uint256)", checkpoint);

        /// Validate the number.
        (uint192 knownThreshold,,,,) = IProxyFirewall(address(mainProxy)).getCheckpoint("withdrawAmount(uint256)");
        assertEq(123, knownThreshold);

        /// The actual proxy firewall should give zero threshold because its storage is empty.
        (knownThreshold,,,,) = proxyFirewall.getCheckpoint("withdrawAmount(uint256)");
        assertEq(0, knownThreshold);

        /// Let's actually use the logic contract at the end of the chain this time.
        /// We treat the main proxy as if it's the logic contract at the end of the chain
        /// and use main proxy storage.
        ILogicContract(address(mainProxy)).withdrawAmount(234);

        /// Verify that only main proxy storage changes with expected values.
        Vm.AccountAccess[] memory accesses = vm.stopAndReturnStateDiff();
        uint256 valueIndex;
        for (uint256 i = 0; i < accesses.length; i++) {
            Vm.AccountAccess memory access = accesses[i];
            // console.log("access", i);
            for (uint256 j = 0; j < access.storageAccesses.length; j++) {
                Vm.StorageAccess memory storageAcc = access.storageAccesses[j];
                if (!storageAcc.isWrite) continue;
                // console.log("storage access", j);
                // console.log("account", storageAcc.account);
                // console.logBytes32(storageAcc.slot);
                // console.logBytes32(storageAcc.newValue);
                assertEq(address(mainProxy), storageAcc.account);
                if (valueIndex == 0) {
                    /// This is the checkpoint threshold value set by the proxy firewall.
                    assertEq(uint256(123), uint192(uint256(storageAcc.newValue)));
                    valueIndex++;
                    continue;
                }
                if (valueIndex == 1) {
                    /// This is the number set by the logic contract.
                    assertEq(uint256(234), uint256(storageAcc.newValue));
                    valueIndex++;
                }
            }
        }

        /// Validate the number.
        uint256 knownNumber = ILogicContract(address(mainProxy)).getNumber();
        assertEq(234, knownNumber);

        /// The actual logic contract should give zero.
        knownNumber = logic.getNumber();
        assertEq(0, knownNumber);

        /// Success!!
        /// So by using a single main proxy, we are able to create a chain.
        /// Then, whenever we treat main proxy as any other contract in the chain,
        /// it works because of the fallback mechanism. Every function on the chain
        /// works only on the storage of the main proxy.
    }

    function testProxyGasChainedActive() public {
        vm.etch(BYPASS_FLAG, bytes("1"));
        ILogicContract(address(mainProxy)).withdrawAmount(234);
    }

    function testProxyGasChainedPassive() public {
        vm.etch(BYPASS_FLAG, bytes("1"));
        ILogicContract(address(mainProxy)).withdrawAmount(10);
    }

    function testProxyGasDirect() public {
        vm.etch(BYPASS_FLAG, bytes("1"));
        ILogicContract(address(altProxy)).withdrawAmount(234);
    }
}
