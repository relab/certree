// SPDX-License-Identifier: MIT
pragma solidity >=0.5.13 <0.7.0;
pragma experimental ABIEncoderV2;

import "../AccountableIssuer.sol";
import "./IssuerMock.sol";

contract AccountableIssuerMock is AccountableIssuer {
    constructor(address[] memory owners, uint256 quorum)
        public
        AccountableIssuer(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function setBalance() public payable {
        // address(this).balance += msg.value;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
