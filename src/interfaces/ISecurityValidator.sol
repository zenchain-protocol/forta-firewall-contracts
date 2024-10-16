// SPDX-License-Identifier: UNLICENSED
// See Forta Network License: https://github.com/forta-network/forta-firewall-contracts/blob/master/LICENSE.md

pragma solidity ^0.8.25;

import "./Attestation.sol";

interface ISecurityValidator {
    function hashAttestation(Attestation calldata attestation) external view returns (bytes32);
    function getCurrentAttester() external view returns (address);
    function validateFinalState() external view;
    function executionHashFrom(bytes32 checkpointHash, address caller, bytes32 executionHash)
        external
        pure
        returns (bytes32);

    function storeAttestation(Attestation calldata attestation, bytes calldata attestationSignature) external;
    function saveAttestation(Attestation calldata attestation, bytes calldata attestationSignature) external;

    function executeCheckpoint(bytes32 checkpointHash) external returns (bytes32);
}
