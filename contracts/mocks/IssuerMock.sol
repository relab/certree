// SPDX-License-Identifier: MIT
pragma solidity >=0.5.13 <0.7.0;

import "../Issuer.sol";

contract IssuerMock is Issuer {
    constructor(address[] memory owners, uint256 quorum)
        public
        Issuer(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function setOwner(address owner) public {
        owners.push(owner);
        isOwner[owner] = true;
    }

    function createSignedLeafCredential(address subject, bytes32 digest) public {
        _issue(subject, digest, bytes32(0), new address[](0));
        issuedCredentials[digest].approved = true;
    }

    function deleteProof(address subject) public {
        root._proofs[subject] = bytes32(0);
    }

}
