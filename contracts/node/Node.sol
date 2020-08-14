// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "../ERC165Checker.sol";
import "../Owners.sol";
import "../notary/Issuer.sol";
import "./NodeInterface.sol";

abstract contract Node is NodeInterface, Owners {
    address immutable _parent;

    Role immutable _role;

    Node[] internal _childrenList;
    
    mapping(address => bool) internal _children;

    Issuer internal _issuer;

    constructor(Role role, address[] memory owners, uint256 quorum)
        Owners(owners, quorum) {
        _parent = msg.sender; // if parent is a contract, then this instance is a leaf or internal node, otherwise parent is a external account address and this instance is the highest root contract.
        _role = role;
        _issuer = new Issuer(owners, quorum);
    }

    /**
     * @return true if the issuer contract is a leaf
     * false otherwise.
     */
    function isLeaf() public view override returns(bool) {
       return _role == Role.Leaf;
    }

    /**
     * @return the address of the parent of this node
     */
    function myParent() public view override returns(address) {
        return _parent;
    }

    /**
     * @return the node role.
     */
    function getRole() public view override returns(Role) {
        return _role;
    }

    /**
     * @param subject The subject of the credential
     * @return the aggregated root of all credentials of a subject
     */
    function getRootProof(address subject) public view returns (bytes32) {
        return _issuer.getRootProof(subject);
    }

    /**
     * @notice verifyCredentialRoot checks whether the root exists
     * and was correctly built based on the existent tree.
     * @param subject The subject of the credential tree
     * @param root The root to be checked.
     */
    function verifyCredentialRoot(address subject, bytes32 root)
        public
        view
        returns (bool) {
            return _issuer.verifyCredentialRoot(subject, root);
    }
}