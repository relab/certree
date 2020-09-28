// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "../Owners.sol";
import "./Ctree.sol";
import "./NodeInterface.sol";

abstract contract Node is NodeInterface, Owners {
    using Ctree for Ctree.Node;
    Ctree.Node internal _node;

    address immutable internal _parent;

    constructor(Role role, address[] memory registrars, uint8 quorum)
        Owners(registrars, quorum)
    {
        require(msg.sender != address(0x0),"Node/sender cannot be 0");
        require(registrars.length > 0,"Node/registrars should not be empty");
        require(
            quorum > 0 && quorum <= registrars.length,
            "Node/quorum out of range"
        );
        _parent = msg.sender; // if parent is a contract, then this instance is a leaf or internal node, otherwise parent is a external account address and this instance is the highest root contract.
        _node.role = role;
    }

    function initialized() public view returns(bool){
        return _node.initialized();
    }

    function initializeIssuer(address issuerAddress) public override onlyOwner returns(bool) {
        return _node.initializeIssuer(issuerAddress);
    }
 
    /**
     * @return the registered issuer contract
     */
    function issuer() public view override returns(address) {
        return address(_node.issuer);
    }

    /**
     * @return true if the issuer contract is a leaf false otherwise.
     */
    function isLeaf() public view override returns(bool) {
       return _node.isLeaf();
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
        return _node.role;
    }

    /**
     * @param subject The subject of the credential
     * @return the aggregated root of all credentials of a subject
     */
    function getRootProof(address subject)
        public
        view
        override
        returns (bytes32)
    {
        return _node.getRootProof(subject);
    }

    /**
     * @notice create a new node on the certification tree
     * @dev The new node can be a Leaf or a Inner node.
     * @param nodeAddress The address of the node
     */
    function addChild(address nodeAddress)
        public
        onlyOwner
        returns (address)
    {
        return _node.addChild(nodeAddress);
    }

    /**
     * @notice register a new credential without witnesses
     * @param subject The subject of the credential
     * @param digest The digest of the credential that is being created
     */
    function registerCredential(
        address subject,
        bytes32 digest,
        address[] memory witnesses
    ) public virtual override onlyOwner {
        return _node.registerCredential(subject, digest, witnesses);
    }

    /**
     * @notice aggregates the digests of a given
     * subject.
     * @param subject The subject of which the credentials will be aggregate
     * @param digests The list of credentials' digests
     */
    function aggregateCredentials(
        address subject,
        bytes32[] memory digests
    ) public virtual override onlyOwner returns (bytes32) {
        return _node.aggregateCredentials(subject, digests);
    }

    /**
     * @notice verifyCredentialRoot checks whether the root exists
     * and was correctly built based on the existent tree.
     * @param subject The subject of the credential tree
     * @param root The root to be checked.
     */
    function verifyCredentialRoot(
        address subject,
        bytes32 root
    ) public view virtual override returns (bool) {
        return _node.verifyCredentialRoot(subject, root);
    }

     /**
     * @notice verifyCredentialTree performs a pre-order tree traversal over
     * the credential tree of a given subject and verifies if the given
     * root match with the current root on the root node and if all the 
     * sub-trees were correctly built.
     * @param subject The subject of the credential tree
     */
    function verifyCredentialTree(address subject) public view override returns(bool) {
        return _node.verifyCredentialTree(subject);
    }

}