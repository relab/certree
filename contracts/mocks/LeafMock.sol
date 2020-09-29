// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "../node/Leaf.sol";
import "./IssuerMock.sol";

contract LeafMock is Leaf {
    constructor(address[] memory registrars, uint8 quorum)
        Leaf(registrars, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function initializeIssuerMock() public {
        address[] memory owners = Node(address(this)).owners();
        uint8 quorum = Node(address(this)).quorum();
        _node.issuer = new IssuerMock(owners, quorum);
        initializeIssuer(address(_node.issuer));
    }

    function createApprovedCredential(address subject, bytes32 digest) public {
        IssuerMock(address(_node.issuer)).createApprovedCredential(subject, digest);
    }

    function resetRoot(address subject) public {
        IssuerMock(address(_node.issuer)).resetRoot(subject);
    }

}
