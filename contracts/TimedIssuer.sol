// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "./notary/Issuer.sol";
import "./Owners.sol";
import "./Timed.sol";

/**
 * @title An Issuer Implementation
 */
contract TimedIssuer is Timed, Owners {

    Issuer private _issuer;

    /**
    * @notice Constructor creates a Issuer contract
    */
    constructor(
        address[] memory owners,
        uint256 quorum,
        uint256 startingTime,
        uint256 endingTime
    ) Timed(startingTime, endingTime) Owners(owners, quorum) {
        _issuer = new Issuer(owners, quorum);
    }

    // TODO: add tests for extenting time
    function extendTime(uint256 NewEndingTime) public onlyOwner {
        _extendTime(NewEndingTime);
    }

    /**
     * @notice register a credential prooffor a given subject
     */
    function registerCredential(address subject, bytes32 digest)
        public
        onlyOwner
        whileNotEnded
    {
        _issuer.register(subject, digest, bytes32(0), new address[](0));
    }

    /**
     * @notice generate the root for a given subject
     */
    function aggregateCredentials(address subject)
        public
        onlyOwner
        returns (bytes32)
    {
        require(hasEnded(), "TimedIssuer/period not ended yet");
        return _issuer.aggregateCredentials(subject);
    }
}
