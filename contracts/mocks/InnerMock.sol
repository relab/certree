// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "../node/Inner.sol";
import "./IssuerMock.sol";

contract InnerMock is Inner {

    constructor(address[] memory registrars, uint8 quorum)
        Inner(registrars, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function initializeIssuerMock() public {
        address[] memory owners = Node(address(this)).owners();
        uint8 quorum = Node(address(this)).quorum();
        _node.issuer = new IssuerMock(owners, quorum);
        initializeIssuer(address(_node.issuer));
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
