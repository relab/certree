// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "./Node.sol";

contract Leaf is Node {

    constructor(address[] memory owners, uint256 quorum)
        Node(Role.Leaf, owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    /**
     * @notice register a new credential without witnesses
     * @param subject The subject of the credential
     * @param digest The digest of the credential that is being created
     */
    function registerCredential(address subject, bytes32 digest)
        public
        onlyOwner
    {
        // TODO: verify the cost of using the following variables instead
        // bytes32 zero;
        // address[] memory none;
        _issuer.register(subject, digest, bytes32(0), new address[](0));
    }
}