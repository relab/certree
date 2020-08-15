// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "../node/Inner.sol";

contract InnerImpl is Inner {

    constructor(address[] memory owners, uint8 quorum)
        Inner(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    // function createIssuer(address[] memory owners, uint256 quorum) public {
    //     IssuerImpl issuer = new IssuerImpl(owners, quorum);
    //     addIssuer(address(issuer));
    //     emit IssuerCreated(address(issuer), msg.sender);
    // }

    // function setBalance() public payable {
    //     // address(this).balance += msg.value;
    // }

    // function getBalance() public view returns (uint256) {
    //     return address(this).balance;
    // }
}
