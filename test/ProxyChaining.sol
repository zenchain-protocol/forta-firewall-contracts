// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console, Vm} from "forge-std/Test.sol";
import "../src/proxy/SecurityProxy.sol";
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

    function setUp() public {
        logic = new LogicContract();

        securityProxy = new SecurityProxy();

        bytes memory data; // empty
        /// Main proxy points to the security proxy.
        mainProxy = new ERC1967Proxy(address(securityProxy), data);

        /// Security proxy points to the logic contract but that should be on main proxy storage.
        ISecurityProxy(address(mainProxy)).setImplementation(address(logic));
    }

    function testStorageWrite() public {
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
}
