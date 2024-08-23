// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @notice Until the attestation can arrive on chain and the user transaction can be executed,
 * the asset amounts that will be processed can fluctuate slightly and cause different hashes
 * to be produced during the real execution and a mismatch with the values in the attestation.
 * This library solves this problem by quantizing the reference value used in checkpoint hash
 * computation.
 */
library Quantization {
    /**
     * @notice Quantizes the given value by getting the most significant byte and multiplying
     * it with the amount of zeroes that would be found if the number was rounded.
     * @param n Input value.
     */
    function quantize(uint256 n) internal pure returns (uint256) {
        if (n == 0) return 0;
        return msb(n) * Math.log10(n);
    }

    /**
     * @notice Finds the most significant byte by starting from the least significant byte.
     * @param n Input value.
     */
    function msb(uint256 n) internal pure returns (uint256) {
        if (n == 0) return 0;
        for (uint256 i = 0; i < 32; i++) {
            if (n < 256) {
                return n;
            }
            n = n >> 8;
        }
        return 0;
    }
}
