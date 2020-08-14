// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "../Leaf.sol";

contract LeafImpl is Leaf {
    constructor(address[] memory owners, uint256 quorum)
        Leaf(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    // function createSignedLeafCredential(address subject, bytes32 digest) public {
    //     _issue(subject, digest, bytes32(0), new address[](0));
    //     issuedCredentials[digest].approved = true;
    // }

    // function deleteProof(address subject) public {
    //     root[subject].proof = bytes32(0);
    //     root[subject].insertedBlock = 0;
    // }

}
