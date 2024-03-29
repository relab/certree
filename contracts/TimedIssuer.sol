// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "./notary/Issuer.sol";
import "./Timed.sol";

/**
 * @title An Issuer Implementation
 */
contract TimedIssuer is Timed, Issuer {
    /**
     * @notice Constructor creates a Issuer contract
     */
    constructor(
        address[] memory owners,
        uint8 quorum,
        uint256 startingTime,
        uint256 endingTime
    ) Timed(startingTime, endingTime) Issuer(owners, quorum) {
        // solhint-disable-previous-line no-empty-blocks
    }

    // TODO: add tests for extenting time
    function extendTime(uint256 newEndingTime) public onlyOwner {
        _extendTime(newEndingTime);
    }

    /**
     * @notice register a credential prooffor a given subject
     */
    function registerCredential(address subject, bytes32 digest) public onlyOwner whileNotEnded {
        _registerCredential(subject, digest, bytes32(0), new address[](0));
    }

    /**
     * @notice generate the root for a given subject
     */
    function aggregateCredentials(address subject, bytes32[] memory digests) public onlyOwner returns (bytes32) {
        require(hasEnded(), "TimedIssuer/period not ended yet");
        return _aggregateCredentials(subject, digests);
    }
}
