// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

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
        uint256 quorum,
        uint256 startingTime,
        uint256 endingTime
    ) Timed(startingTime, endingTime) Issuer(owners, quorum) {
        // solhint-disable-previous-line no-empty-blocks
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
        _register(subject, digest, bytes32(0), new address[](0));
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    /**
     * @notice generate the root for a given subject
     */
    function aggregateCredentials(address subject)
        public
        override
        onlyOwner
        returns (bytes32)
    {
        require(hasEnded(), "IssuerImpl: IssuerImpl not ended yet");
        return super.aggregateCredentials(subject);
    }
}
