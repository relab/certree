// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "../notary/Issuer.sol";

contract IssuerMock is Issuer {
    uint256 public balance;

    constructor(address[] memory registrars, uint8 quorum) Issuer(registrars, quorum) {
        // solhint-disable-previous-line no-empty-blocks
    }

    function createApprovedCredential(address subject, bytes32 digest) public {
        _registerCredential(subject, digest, bytes32(0), new address[](0));
        _tree.records[digest].approved = true;
    }

    function resetRoot(address subject) public {
        _root[subject].proof = bytes32(0);
        _root[subject].insertedBlock = 0;
    }

    function setBalance() public payable {
        balance += msg.value;
    }

        function registerCredential(
        address subject,
        bytes32 digest,
        bytes32 eRoot,
        address[] memory witnesses
    ) public {
        _registerCredential(subject, digest, eRoot, witnesses);
    }

    function aggregateCredentials(address subject, bytes32[] memory digests) public returns (bytes32) {
        return _aggregateCredentials(subject, digests);
    }

    function approveCredential(bytes32 digest) public {
        _approveCredential(digest);
    }

    function revokeCredential(bytes32 digest, bytes32 reason) public {
        _revokeCredential(digest, reason);
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    function getRoot(address subject) public view returns (bytes32) {
        return _getRoot(subject);
    }

    function verifyCredentialRoot(address subject, bytes32 root) public view returns (bool) {
        return _verifyCredentialRoot(subject, root);
    }

}
