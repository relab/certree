// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "../node/Leaf.sol";
import "./IssuerMock.sol";

contract LeafMock is Leaf {
    constructor(address[] memory registrars, uint8 quorum) Leaf(registrars, quorum) {
        // solhint-disable-previous-line no-empty-blocks
    }

    function createApprovedCredential(address subject, bytes32 digest) public {
        IssuerMock(address(this)).createApprovedCredential(subject, digest);
    }

    function resetRoot(address subject) public {
        IssuerMock(address(this)).resetRoot(subject);
    }
}
