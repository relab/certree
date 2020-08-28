// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;
pragma experimental ABIEncoderV2;

import "../notary/Issuer.sol";

contract IssuerMock is Issuer {
    uint public balance;

    constructor(address[] memory registrars, uint8 quorum)
        Issuer(registrars, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function createApprovedCredential(address subject, bytes32 digest) public {
        registerCredential(subject, digest, bytes32(0), new address[](0));
        _tree.records[digest].approved = true;
    }

    function resetRoot(address subject) public {
        _root[subject].proof = bytes32(0);
        _root[subject].insertedBlock = 0;
    }

    function setBalance() public payable {
        balance += msg.value;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
