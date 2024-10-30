// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console, Vm} from "forge-std/Test.sol";
import {ISecurityValidator} from "../src/interfaces/ISecurityValidator.sol";
import {
    Deployer as ProxyFirewallDeployer,
    ProtectedContract as ProxyProtectedContract
} from "../src/examples/ProxyFirewallIntegration.sol";
import {
    Deployer as InternalFirewallDeployer,
    ProtectedContract as InternalProtectedContract
} from "../src/examples/InternalFirewallIntegration.sol";
import {
    Deployer as ExternalFirewallDeployer,
    ProtectedContract as ExternalProtectedContract
} from "../src/examples/ExternalFirewallIntegration.sol";

/// @notice All integration examples should work and a call to the protected function
/// should cause a checkpoint to be executed and the trusted attester to be read and accepted.
contract ExamplesTest is Test {
    address mockValidator = address(uint160(987));
    address trustedAttester = address(uint160(876));

    function testExampleProxyFirewall() public {
        vm.mockCall(
            mockValidator,
            abi.encodeWithSelector(
                ISecurityValidator.executeCheckpoint.selector,
                0xfbfc6284bb2eee0d842ee164124d3faed8c782b94920c6bfb9c7dbf2fe70f667
            ),
            abi.encode(bytes32(0))
        );
        vm.mockCall(
            mockValidator,
            abi.encodeWithSelector(ISecurityValidator.getCurrentAttester.selector),
            abi.encode(trustedAttester)
        );
        ProxyFirewallDeployer deployer = new ProxyFirewallDeployer();
        ProxyProtectedContract protectedContract =
            deployer.deploy(ISecurityValidator(mockValidator), address(0), trustedAttester, bytes32(uint256(0)));
        protectedContract.foo(123);
    }

    function testExampleInternalFirewall() public {
        vm.mockCall(
            mockValidator,
            abi.encodeWithSelector(
                ISecurityValidator.executeCheckpoint.selector,
                0x5f57ccc48e109c6e67f0399df70f1efbb06300a2b6c986921475180af9dc2b37
            ),
            abi.encode(bytes32(0))
        );
        vm.mockCall(
            mockValidator,
            abi.encodeWithSelector(ISecurityValidator.getCurrentAttester.selector),
            abi.encode(trustedAttester)
        );
        InternalFirewallDeployer deployer = new InternalFirewallDeployer();
        InternalProtectedContract protectedContract =
            deployer.deploy(ISecurityValidator(mockValidator), address(0), trustedAttester, bytes32(uint256(0)));
        protectedContract.foo(123);
    }

    function testExampleExternalFirewall() public {
        vm.mockCall(
            mockValidator,
            abi.encodeWithSelector(
                ISecurityValidator.executeCheckpoint.selector,
                0x9c0c80e7e1ccffd74a4d9a89a1635e07c9ab9e0a60929e703aa093eb29472f9c
            ),
            abi.encode(bytes32(0))
        );
        vm.mockCall(
            mockValidator,
            abi.encodeWithSelector(ISecurityValidator.getCurrentAttester.selector),
            abi.encode(trustedAttester)
        );
        ExternalFirewallDeployer deployer = new ExternalFirewallDeployer();
        ExternalProtectedContract protectedContract =
            deployer.deploy(ISecurityValidator(mockValidator), address(0), trustedAttester, bytes32(uint256(0)));
        protectedContract.foo(123);
    }
}
