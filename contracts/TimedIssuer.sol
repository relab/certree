// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "./Issuer.sol";
import "./Timed.sol";

/**
 * @title An Issuer Implementation
 */
contract TimedIssuer is Timed, Issuer {
    /**
    * @dev Constructor creates a Issuer contract
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
     * @dev issue a credential proof for enrolled students
     */
    function registerCredential(address subject, bytes32 digest)
        public
        override
        onlyOwner
        whileNotEnded
    {
        _issue(subject, digest, bytes32(0), new address[](0));
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    // FIXME: only allow onwer to call the aggregation? If so, the faculty contract will not be able to call the method, and the teacher will need to call it
    function aggregateCredentials(address student)
        public
        override
        returns (bytes32)
    {
        require(hasEnded(), "IssuerImpl: IssuerImpl not ended yet");
        return super.aggregateCredentials(student);
    }
}
