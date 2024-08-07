// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console, Vm} from "forge-std/Test.sol";
import "../src/SecurityProxy.sol";
import {ISecurityValidator, SecurityValidator, BYPASS_FLAG} from "../src/SecurityValidator.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

interface ILogicContract {
    function setNumber(uint256 n) external;
    function getNumber() external view returns (uint256);
}

contract LogicContract {
    uint256 number;

    function setNumber(uint256 n) public {
        number = n;
    }

    function getNumber() public view returns (uint256) {
        return number;
    }
}

contract ProxyChainingTest is Test {
    ERC1967Proxy mainProxy;
    SecurityProxy securityProxy;
    LogicContract logic;

    ERC1967Proxy altProxy;

    function setUp() public {
        logic = new LogicContract();

        securityProxy = new SecurityProxy();

        bytes memory data; // empty
        /// Main proxy points to the security proxy.
        mainProxy = new ERC1967Proxy(address(securityProxy), data);

        /// Security proxy points to the logic contract but that should be on main proxy storage.
        ISecurityProxy(address(mainProxy)).setNextImplementation(address(logic));
        ISecurityProxy(address(mainProxy)).setSecurityValidator(ISecurityValidator(address(new SecurityValidator())));
        vm.etch(BYPASS_FLAG, bytes("1"));

        /// Keep a default threshold for every test.
        ISecurityProxy(address(mainProxy)).setCheckpointThreshold("setNumber(uint256)", 123);

        /// Define an alternative main proxy that directly integrates with the logic contract.
        altProxy = new ERC1967Proxy(address(logic), data);
    }

    function testStorageWrite() public {
        vm.startStateDiffRecording();

        /// Let's change the threshold of the security proxy but on main proxy storage.
        /// That should work because the implementation of main proxy is the security proxy.
        /// So we can treat main proxy as if it's the security proxy.
        ISecurityProxy(address(mainProxy)).setCheckpointThreshold("setNumber(uint256)", 123);

        /// Validate the number.
        uint256 knownThreshold = ISecurityProxy(address(mainProxy)).getCheckpointThreshold("setNumber(uint256)");
        assertEq(123, knownThreshold);

        /// The actual security proxy should give zero threshold because its storage is empty.
        knownThreshold = securityProxy.getCheckpointThreshold("setNumber(uint256)");
        assertEq(0, knownThreshold);

        /// Let's actually use the logic contract at the end of the chain this time.
        /// We treat the main proxy as if it's the logic contract at the end of the chain
        /// and use main proxy storage.
        ILogicContract(address(mainProxy)).setNumber(234);

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
                    assertEq(uint256(123), uint256(storageAcc.newValue));
                    valueIndex++;
                    continue;
                }
                if (valueIndex == 1) {
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

        /// The security proxy should also give zero.
        securityProxy.setNextImplementation(address(logic));
        knownNumber = ILogicContract(address(securityProxy)).getNumber();
        assertEq(0, knownNumber);

        /// Success!!
        /// So by using a single main proxy, we are able to create a chain.
        /// Then, whenever we treat main proxy as any other contract in the chain,
        /// it works because of the fallback mechanism. Every function on the chain
        /// works only on the storage of the main proxy.
    }

    function testProxyGasChainedActive() public {
        ILogicContract(address(mainProxy)).setNumber(234);
    }

    function testProxyGasChainedPassive() public {
        ILogicContract(address(mainProxy)).setNumber(10);
    }

    function testProxyGasDirect() public {
        ILogicContract(address(altProxy)).setNumber(234);
    }
}
