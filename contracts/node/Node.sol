// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "../Owners.sol";
import "../notary/Issuer.sol";
import "./NodeInterface.sol";

abstract contract Node is NodeInterface, Owners {

    bool internal _init = false;

    Role immutable _role;

    address immutable _parent;

    address[] internal _childrenList;
    
    mapping(address => bool) internal _children;

    IssuerInterface internal _issuer;

    event IssuerInitialized(address indexed _issuer, address indexed by);

    constructor(Role role, address[] memory registrars, uint8 quorum)
        Owners(registrars, quorum) {
        _parent = msg.sender; // if parent is a contract, then this instance is a leaf or internal node, otherwise parent is a external account address and this instance is the highest root contract.
        //TODO: check if is zero
        _role = role;
    }

    modifier isInitialized() {
        require(initialized(), "Node/notarization not initialized");
        _;
    }

    function initialized() public view returns(bool){
        return _init;
    }

    function initializeIssuer() public virtual override onlyOwner {
        require(!initialized(), "Node/notarization already initialized");
        _issuer = new Issuer(_owners, _quorum);
        _init = true;
        emit IssuerInitialized(address(_issuer), msg.sender);
    }

    /**
     * @return the registered issuer contract
     */
    function issuer() public view override returns(address) {
        return address(_issuer);
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
    function getRootProof(address subject) public view isInitialized returns (bytes32) {
        return _issuer.getRootProof(subject);
    }

    /**
     * @notice register a new credential without witnesses
     * @param subject The subject of the credential
     * @param digest The digest of the credential that is being created
     */
    function registerCredential(address subject, bytes32 digest)
        public
        virtual
        onlyOwner
        isInitialized
    {
        _issuer.registerCredential(subject, digest, bytes32(0), new address[](0));
    }

    /**
     * @notice aggregates the digests of a given
     * subject.
     * @param subject The subject of which the credentials will be aggregate
     * @param digests The list of credentials' digests
     */
    function aggregateCredentials(address subject, bytes32[] memory digests)
        public
        virtual
        onlyOwner
        isInitialized
        returns (bytes32)
    {
        return _issuer.aggregateCredentials(subject, digests);
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
        virtual
        isInitialized
        returns (bool) {
            return _issuer.verifyCredentialRoot(subject, root);
    }
}