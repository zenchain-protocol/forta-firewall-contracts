// SPDX-License-Identifier: UNLICENSED
// See Forta Network License: https://github.com/forta-network/forta-firewall-contracts/blob/master/LICENSE.md

pragma solidity ^0.8.25;

interface IAttesterInfo {
    event AttesterControllerUpdated(bytes32 indexed attesterControllerId);

    function getAttesterControllerId() external view returns (bytes32);
}
