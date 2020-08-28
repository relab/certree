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

    function initializeIssuer() public override onlyOwner {
        require(!initialized(), "Node/notarization already initialized");
        _issuer = new IssuerMock(_owners, _quorum);
        _init = true;
        emit IssuerInitialized(address(_issuer), msg.sender);
    }

    function createApprovedCredential(address subject, bytes32 digest) public {
        IssuerMock(address(_issuer)).createApprovedCredential(subject, digest);
    }

    function resetRoot(address subject) public {
        IssuerMock(address(_issuer)).resetRoot(subject);
    }

}
