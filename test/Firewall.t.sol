// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console, Vm} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Firewall} from "../src/Firewall.sol";
import {Checkpoint, Activation} from "../src/Firewall.sol";
import {
    IFirewallAccess,
    FIREWALL_ADMIN_ROLE,
    PROTOCOL_ADMIN_ROLE,
    ATTESTER_MANAGER_ROLE,
    TRUSTED_ATTESTER_ROLE
} from "../src/FirewallAccess.sol";
import {ISecurityValidator, Attestation} from "../src/SecurityValidator.sol";
import {Quantization} from "../src/Quantization.sol";

contract FirewallImpl is Firewall {
    constructor(ISecurityValidator _validator, bytes32 _attesterControllerId, IFirewallAccess _firewallAccess) {
        _updateFirewallConfig(_validator, _attesterControllerId, _firewallAccess);
    }
}

contract FirewallTest is Test {
    bytes32 constant attesterControllerId = bytes32(uint256(123));

    address constant mockValidator = address(uint160(234));
    address constant mockAccess = address(uint160(345));

    FirewallImpl firewall;

    Checkpoint checkpoint =
        Checkpoint({threshold: 1, refStart: 2, refEnd: 3, activation: Activation.AlwaysActive, trustedOrigin: true});

    function setUp() public {
        firewall =
            new FirewallImpl(ISecurityValidator(mockValidator), attesterControllerId, IFirewallAccess(mockAccess));
    }

    function testFirewall_setCheckpointWithSelector() public {
        vm.mockCall(
            address(mockAccess),
            abi.encodeWithSelector(IFirewallAccess.isCheckpointManager.selector, address(this)),
            abi.encode(true)
        );
        firewall.setCheckpoint(0xaaaaaaaa, checkpoint);
        (uint192 threshold, uint16 refStart, uint16 refEnd, Activation activation, bool trustedOrigin) =
            firewall.getCheckpoint(0xaaaaaaaa);
        assertEq(checkpoint.threshold, threshold);
        assertEq(checkpoint.refStart, refStart);
        assertEq(checkpoint.refEnd, refEnd);
        assertEq(uint8(checkpoint.activation), uint8(activation));
        assertEq(checkpoint.trustedOrigin, trustedOrigin);

        vm.mockCall(
            address(mockAccess),
            abi.encodeWithSelector(IFirewallAccess.isCheckpointManager.selector, address(this)),
            abi.encode(true)
        );
        firewall.setCheckpointActivation(0xaaaaaaaa, Activation.AlwaysBlocked);
        (,,, activation,) = firewall.getCheckpoint(0xaaaaaaaa);
        assertEq(uint8(Activation.AlwaysBlocked), uint8(activation));

        /// Refuse access.
        vm.mockCall(
            address(mockAccess),
            abi.encodeWithSelector(IFirewallAccess.isCheckpointManager.selector, address(this)),
            abi.encode(false)
        );
        vm.expectRevert();
        firewall.setCheckpoint(0xaaaaaaaa, checkpoint);

        /// Refuse access.
        vm.mockCall(
            address(mockAccess),
            abi.encodeWithSelector(IFirewallAccess.isCheckpointManager.selector, address(this)),
            abi.encode(false)
        );
        vm.expectRevert();
        firewall.setCheckpointActivation(0xaaaaaaaa, Activation.AlwaysBlocked);
    }

    function testFirewall_setCheckpointWithSignature() public {
        vm.mockCall(
            address(mockAccess),
            abi.encodeWithSelector(IFirewallAccess.isCheckpointManager.selector, address(this)),
            abi.encode(true)
        );
        firewall.setCheckpoint("foo()", checkpoint);
        (uint192 threshold, uint16 refStart, uint16 refEnd, Activation activation, bool trustedOrigin) =
            firewall.getCheckpoint("foo()");
        assertEq(checkpoint.threshold, threshold);
        assertEq(checkpoint.refStart, refStart);
        assertEq(checkpoint.refEnd, refEnd);
        assertEq(uint8(checkpoint.activation), uint8(activation));
        assertEq(checkpoint.trustedOrigin, trustedOrigin);

        vm.mockCall(
            address(mockAccess),
            abi.encodeWithSelector(IFirewallAccess.isCheckpointManager.selector, address(this)),
            abi.encode(true)
        );
        firewall.setCheckpointActivation("foo()", Activation.AlwaysBlocked);
        (,,, activation,) = firewall.getCheckpoint("foo()");
        assertEq(uint8(Activation.AlwaysBlocked), uint8(activation));

        /// Refuse access.
        vm.mockCall(
            address(mockAccess),
            abi.encodeWithSelector(IFirewallAccess.isCheckpointManager.selector, address(this)),
            abi.encode(false)
        );
        vm.expectRevert();
        firewall.setCheckpoint("foo()", checkpoint);

        /// Refuse access.
        vm.mockCall(
            address(mockAccess),
            abi.encodeWithSelector(IFirewallAccess.isCheckpointManager.selector, address(this)),
            abi.encode(false)
        );
        vm.expectRevert();
        firewall.setCheckpointActivation("foo()", Activation.AlwaysBlocked);
    }

    function testFirewall_getAttesterControllerId() public view {
        assertEq(attesterControllerId, firewall.getAttesterControllerId());
    }

    function testFirewall_updateFirewallConfig() public {
        address newValidator = address(uint160(777));
        bytes32 newControllerId = bytes32(uint256(888));
        address newAccess = address(uint160(999));

        /// Refuse access.
        vm.mockCall(
            address(mockAccess),
            abi.encodeWithSelector(IFirewallAccess.isFirewallAdmin.selector, address(this)),
            abi.encode(false)
        );
        vm.expectRevert();
        firewall.updateFirewallConfig(ISecurityValidator(newValidator), newControllerId, IFirewallAccess(newAccess));

        /// Grant access.
        vm.mockCall(
            address(mockAccess),
            abi.encodeWithSelector(IFirewallAccess.isFirewallAdmin.selector, address(this)),
            abi.encode(true)
        );
        firewall.updateFirewallConfig(ISecurityValidator(newValidator), newControllerId, IFirewallAccess(newAccess));

        (ISecurityValidator validator, bytes32 controllerId, IFirewallAccess access) = firewall.getFirewallConfig();
        assertEq(newValidator, address(validator));
        assertEq(newControllerId, controllerId);
        assertEq(newAccess, address(access));
    }
}
