// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;
pragma experimental ABIEncoderV2;

import "./Issuer.sol";
import "./Node.sol";

contract Leaf is Node, Issuer {

    constructor(address[] memory owners, uint256 quorum)
        Node(Role.Leaf)
        Issuer(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function registerCredential(address subject, bytes32 digest)
        public
        override
        onlyOwner
    {
        // TODO: verify the cost of using the following variables instead
        // bytes32 zero;
        // address[] memory none;
        _issue(subject, digest, bytes32(0), new address[](0));
        emit CredentialSigned(msg.sender, digest, block.number);
    }
}