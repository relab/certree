// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

import "../AccountableIssuer.sol";
import "./IssuerMock.sol";

contract AccountableIssuerMock is AccountableIssuer {
    // Logged when an issuer created.
    event IssuerCreated(
        address indexed issuerAddress,
        address indexed createdBy
    );

    constructor(address[] memory owners, uint256 quorum)
        public
        AccountableIssuer(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function createIssuer(address[] memory owners, uint256 quorum) public {
        IssuerMock issuer = new IssuerMock(owners, quorum);
        addIssuer(address(issuer));
        emit IssuerCreated(address(issuer), msg.sender);
    }

    function setBalance() public payable {
        // address(this).balance += msg.value;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
