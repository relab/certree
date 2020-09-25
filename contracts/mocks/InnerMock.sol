// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "../node/Leaf.sol";
import "../node/Inner.sol";
import "./IssuerMock.sol";

contract InnerMock is Inner {

    constructor(address[] memory registrars, uint8 quorum)
        Inner(registrars, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function initializeIssuer() public override onlyOwner {
        require(!initialized(), "Node/already initialized");
        _issuer = new IssuerMock(_owners, _quorum);
        emit IssuerInitialized(address(_issuer), msg.sender);
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
