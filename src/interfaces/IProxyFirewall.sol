// SPDX-License-Identifier: UNLICENSED
// See Forta Network License: https://github.com/forta-network/forta-firewall-contracts/blob/master/LICENSE.md

pragma solidity ^0.8.25;

import "./IFirewall.sol";

interface IProxyFirewall is IFirewall {
    function initializeFirewallConfig(
        ISecurityValidator _validator,
        ICheckpointHook _checkpointHook,
        bytes32 _attesterControllerId,
        IFirewallAccess _firewallAccess
    ) external;

    function upgradeNextAndCall(address newImplementation, bytes memory data) external payable;
}
