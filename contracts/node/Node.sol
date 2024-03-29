// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "../ERC165.sol";
import "../ERC165Checker.sol";
import "./Node.sol";
import "./NodeInterface.sol";
import "../notary/Issuer.sol";

contract Node is NodeInterface, Issuer, ERC165 {
    bytes4[] private _supportedInterfaces = [type(NodeInterface).interfaceId];
    address internal immutable _parent;

    Role internal _role;

    address[] internal _children;

    mapping(address => bool) internal _isChild;

    constructor(
        Role role,
        address[] memory registrars,
        uint8 quorum
    ) Issuer(registrars, quorum) {
        require(msg.sender != address(0x0), "Node/sender cannot be 0");
        _parent = msg.sender; // if parent is a contract, then this instance is a leaf or internal node, otherwise parent is a external account address and this instance is the highest root contract.
        _role = role;
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(ERC165).interfaceId || interfaceId == type(NodeInterface).interfaceId;
    }

    /**
     * @return true if the contract is a leaf false otherwise.
     */
    function isLeaf() public view override returns (bool) {
        return _role == Role.Leaf;
    }

    /**
     * @notice checks whether the given node is a child of this node.
     */
    function isChild(address node) public view override returns (bool) {
        return _isChild[node];
    }

    /**
     * @return the address of the parent of this node
     */
    function myParent() public view override returns (address) {
        return _parent;
    }

    /**
     * @return the node role.
     */
    function getRole() public view override returns (Role) {
        return _role;
    }

    /**
     * @return the list of children nodes' addresses.
     */
    function getChildren() public view returns (address[] memory) {
        return _children;
    }

    /**
     * @param subject The subject of the credential
     * @return the aggregated root of all credentials of a subject
     */
    function getRoot(address subject) public view override returns (bytes32) {
        return _getRoot(subject);
    }

    //TODO: Remove nodes (require quorum)

    /**
     * @notice create a new node on the certification tree
     * @param nodeAddress The address of the node
     * @dev The new node can be a Leaf or a Inner node.
     * This function checks if the account address implements the
     * NodeInterface, but this is not sufficient to ensure the
     * correctness of the implementation.
     * Malicious contracts that match such interfaces can still
     * be added and further checks of the contract code should be
     * performed before approval of the inclusion.
     */
    function addChild(address nodeAddress) public override onlyOwner {
        // TODO: require a quorum of registrars?
        require(_role == Role.Inner, "Node/node must be Inner");

        bool isNodeLike = ERC165Checker.supportsAllInterfaces(address(this), _supportedInterfaces);
        assert(isNodeLike);

        NodeInterface node = NodeInterface(nodeAddress);
        Role role = node.getRole();
        //FIXME: Assert if owners are different?
        _addNode(nodeAddress, role);
    }

    /**
     * @notice register a new credential with witnesses
     * @param subject The subject of the credential
     * @param digest The digest of the credential that is being created
     * @param witnesses The list of nodes that are children of this
     * inned contract and will be used as witnesses for the credential
     * creation.
     * @dev The subject must be the same on the given witnesses nodes
     */
    function registerCredential(
        address subject,
        bytes32 digest,
        address[] memory witnesses
    )
        public
        override
        onlyOwner // FIXME: the number of witnesses should be bounded to avoid gas limit on loops
    {
        if (_role == Role.Leaf) {
            require(witnesses.length == 0, "Node/Leaf cannot have witnesses");
            _registerCredential(subject, digest, bytes32(0), new address[](0));
        } else {
            assert(_role == Role.Inner);
            require(witnesses.length > 0, "Node/witness not found");
            bytes32[] memory witenessProofs = new bytes32[](witnesses.length);
            // TODO: limit the size of witnesses
            for (uint256 i = 0; i < witnesses.length; i++) {
                address nodeAddress = address(witnesses[i]);
                require(_isChild[nodeAddress], "Node/address not authorized");
                bool isNodeLike = ERC165Checker.supportsInterface(nodeAddress, type(NodeInterface).interfaceId);
                assert(isNodeLike);
                NodeInterface node = NodeInterface(nodeAddress);
                //TODO: check for re-entrancy
                bytes32 root = node.getRoot(subject);
                // TODO: check the time of the creation of the roots on the witnesses? And only allow roots that have a order between them.
                // bytes32 proof = node.getProof(subject);
                // i.e. root[subject].insertedBlock and root[subject].blockTimestamp
                require(root != bytes32(0), "Node/root not found");
                witenessProofs[i] = root;
            }
            // FIXME: Not allow reuse of witness at same contract? keep a map of witnesses?
            // FIXME: consider use sha256(abi.encodePacked(roots, digests));
            bytes32 evidenceRoot = CredentialSum.computeRoot(witenessProofs);
            _registerCredential(subject, digest, evidenceRoot, witnesses);
        }
    }

    /**
     * @notice approves the emission of a quorum signed credential proof
     * @param digest The digest of the credential
     */
    function approveCredential(bytes32 digest) public override {
        _approveCredential(digest);
    }

    /**
     * @notice revokes a credential for a given reason
     * based on it's digest.
     * @param digest The digest of the credential
     * @param reason The hash of the reason of the revocation
     * @dev The reason should be publicaly available for anyone to inspect
     * i.e. Stored in a public swarm/ipfs address
     */
    function revokeCredential(bytes32 digest, bytes32 reason) public override onlyOwner {
        _revokeCredential(digest, reason);
    }

    /**
     * @notice aggregates the digests of a given
     * subject.
     * @param subject The subject of which the credentials will be aggregate
     * @param digests The list of credentials' digests
     */
    function aggregateCredentials(address subject, bytes32[] memory digests)
        public
        override
        onlyOwner
        returns (bytes32)
    {
        return _aggregateCredentials(subject, digests);
    }

    // TODO: move verification to another contract
    /**
     * @notice checks whether the root exists
     * and was correctly built based on the existent tree.
     * @param subject The subject of the credential tree
     * @param root The root to be checked.
     */
    function verifyCredentialRoot(address subject, bytes32 root) public view override returns (bool) {
        return _verifyCredentialRoot(subject, root);
    }

    /**
     * @notice verifyCredentialTree performs a pre-order tree traversal over
     * the credential tree of a given subject and verifies if the given
     * root match with the current root on the root node and if all the
     * sub-trees were correctly built.
     * @param subject The subject of the credential tree
     */
    function verifyCredentialTree(address subject) public view override returns (bool) {
        bytes32[] memory digests = getDigests(subject);
        require(digests.length > 0, "Node/credential not found");
        // Verify local root if exists
        if (hasRoot(subject)) {
            if (!verifyRootOf(subject, digests)) {
                return false;
            }
        }
        // Verify credential and potential subtrees
        for (uint256 i = 0; i < digests.length; i++) {
            assert(recordExists(digests[i]));
            if (!verifyCredential(subject, digests[i])) {
                return false;
            }
            if (_role == Role.Inner && witnessesLength(digests[i]) > 0) {
                if (!_verifyCredentialNode(subject, getEvidenceRoot(digests[i]), getWitnesses(digests[i]))) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * @notice verifyCredentialNode iteractivally verifies if a given
     * credential proof (represented by it's digest) corresponds to
     * the aggregation of all stored proofs of a particular subject
     * in all given sub-contracts.
     * @param subject is the subject referred by all credentials to be verified
     * @param croot is the current credential root for the given subject
     * @param witnesses is an array with the address of all authorized
     * issuers that stores the subject sub-credentials
     */
    function _verifyCredentialNode(
        address subject,
        bytes32 croot,
        address[] memory witnesses
    ) private view returns (bool) {
        require(croot != bytes32(0), "Node/root cannot be null");
        bytes32[] memory proofs = new bytes32[](witnesses.length);
        for (uint256 i = 0; i < witnesses.length; i++) {
            address witnessesAddress = address(witnesses[i]);
            require(_isChild[witnessesAddress], "Node/address not authorized");
            bool isNodeLike = ERC165Checker.supportsInterface(witnessesAddress, type(NodeInterface).interfaceId);
            assert(isNodeLike);
            NodeInterface node = NodeInterface(witnessesAddress);
            if (node.isLeaf()) {
                proofs[i] = node.getRoot(subject);
                if (!node.verifyCredentialRoot(subject, proofs[i])) {
                    return false;
                }
            } else {
                // witness is a node, check sub-tree
                if (!node.verifyCredentialTree(subject)) {
                    return false;
                }
            }
        }
        return CredentialSum.verifyRoot(croot, proofs);
    }

    /**
     * @notice addNode adds a contract node to the certification tree.
     * @param nodeAddress The address of the new node to be added
     */
    // FIXME: - require a quorum of owners
    //        - not allow adding node where the sender is an owner of the parent
    //        - this function can be used by derivants to allows cycles,
    // and there is no easy way to detect it other than going through all children of `nodeAddress` and checking if any reference this.
    function _addNode(address nodeAddress, Role role) private {
        require(address(this) != nodeAddress, "Node/cannot add itself");
        require(!_isChild[nodeAddress], "Node/node already added");
        require(role == Role.Leaf || role == Role.Inner, "Node/invalid child role");
        _isChild[nodeAddress] = true;
        _children.push(nodeAddress);
        emit NodeAdded(msg.sender, nodeAddress, role);
    }
}
