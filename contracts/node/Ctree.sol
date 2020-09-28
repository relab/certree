// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "../ERC165Checker.sol";
import "../aggregator/CredentialSum.sol";
import "../notary/Issuer.sol";
import "./NodeInterface.sol";

library Ctree {
    struct Node {
        Role role;
        IssuerInterface issuer;
        address[] children;
        mapping(address => bool) isChild;
    }

    event NodeAdded(
        address indexed createdBy,
        address indexed nodeAddress,
        Role role
    );

    event IssuerInitialized(address indexed issuer, address indexed by);

    modifier isInitialized(Node storage self) {
        require(initialized(self), "Ctree/not initialized");
        _;
    }

    function initialized(Node storage self) internal view returns (bool) {
        return address(self.issuer) != address(0x0);
    }

    function initializeIssuer(Node storage self, address issuerAddress)
        internal
        returns (bool)
    {
        require(!initialized(self), "Ctree/already initialized");
        bool isIssuerLike = ERC165Checker.supportsInterface(
            issuerAddress,
            type(IssuerInterface).interfaceId
        );
        assert(isIssuerLike);
        // FIXME: ensure that the owners of the issuer contract are the same of the node contract.
        self.issuer = Issuer(issuerAddress);
        emit IssuerInitialized(address(self.issuer), msg.sender);
        return initialized(self);
    }

    /**
     * @return true if the issuer contract is a leaf false otherwise.
     */
    function isLeaf(Node storage self) external view returns (bool) {
        return self.role == Role.Leaf;
    }

    /**
     * @param subject The subject of the credential
     * @return the aggregated root of all credentials of a subject
     */
    function getRootProof(Node storage self, address subject)
        public
        view
        isInitialized(self)
        returns (bytes32)
    {
        return self.issuer.getRootProof(subject);
    }

    /**
     * @notice addNode adds a contract node to the certification tree.
     * @param nodeAddress The address of the new node to be added
     * @dev This function checks if the account address implements the
     * IssuerInterface and NodeInterface, but this is not
     * sufficient to ensure the correctness of the implementation itself.
     * Malicious contracts that match such interfaces can still
     * be added and further checks of the contract code should be
     * performed before approval of the inclusion.
     */
    // FIXME: - require a quorum of owners
    //        - not allow adding node where the sender is an owner of the parent
    //        - this function can be used by derivants to allows cycles,
    // and there is no easy way to detect it other than going through all children of `nodeAddress` and checking if any reference this.
    function _addNode(Node storage self, address nodeAddress) private {
        require(address(this) != nodeAddress, "Ctree/cannot add itself");
        require(!self.isChild[nodeAddress], "Ctree/node already added");
        self.isChild[nodeAddress] = true;
        self.children.push(nodeAddress);
    }

    //TODO: Remove nodes (require quorum)

    /**
     * @notice create a new node on the certification tree
     * @dev The new node can be a Leaf or a Inner node.
     * @param nodeAddress The address of the node
     */
    function addChild(Node storage self, address nodeAddress)
        internal
        returns (address)
    {
        // TODO: require a quorum of registrars?
        require(self.role == Role.Inner, "Ctree/node must be Inner");

        bool isNodeLike = ERC165Checker.supportsInterface(
            nodeAddress,
            type(NodeInterface).interfaceId
        );
        assert(isNodeLike);

        NodeInterface node = NodeInterface(nodeAddress);
        require(node.issuer() != address(0x0), "Ctree/child not initialized");
        bool isIssuerLike = ERC165Checker.supportsInterface(
            node.issuer(),
            type(IssuerInterface).interfaceId
        );
        assert(isIssuerLike);

        Role role = node.getRole();
        require(
            role == Role.Leaf || role == Role.Inner,
            "Ctree/invalid child role"
        );
        //FIXME: Assert if owners are different?
        _addNode(self, nodeAddress);
        emit NodeAdded(msg.sender, nodeAddress, role);
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
        Node storage self,
        address subject,
        bytes32 digest,
        address[] memory witnesses
    )
        public
        isInitialized(self)
    // FIXME: the number of witnesses should be bounded to avoid gas limit on loops
    {
        if (self.role == Role.Leaf) {
            require(witnesses.length == 0, "Ctree/Leaf cannot have witnesses");
            self.issuer.registerCredential(
                subject,
                digest,
                bytes32(0),
                new address[](0)
            );
        } else {
            assert(self.role == Role.Inner);
            require(witnesses.length > 0, "Ctree/witness not found");
            bytes32[] memory witenessProofs = new bytes32[](witnesses.length);
            for (uint256 i = 0; i < witnesses.length; i++) {
                address nodeAddress = address(witnesses[i]);
                require(
                    self.isChild[nodeAddress],
                    "Ctree/address not authorized"
                );
                bool success = ERC165Checker.supportsInterface(
                    nodeAddress,
                    type(IssuerInterface).interfaceId
                );
                assert(success);
                Issuer issuer = Issuer(nodeAddress);
                //TODO: check for re-entrancy
                bytes32 proof = issuer.getRootProof(subject);
                // TODO: check the time of the creation of the roots on the witnesses? And only allow roots that have a order between them.
                // i.e. root[subject].insertedBlock and root[subject].blockTimestamp
                require(proof != bytes32(0), "Ctree/root not found");
                witenessProofs[i] = proof;
            }
            // FIXME: Not allow reuse of witness at same contract? keep a map of witnesses?
            // FIXME: consider use sha256(abi.encodePacked(roots, digests));
            bytes32 evidencesRoot = CredentialSum.computeRoot(witenessProofs);
            self.issuer.registerCredential(
                subject,
                digest,
                evidencesRoot,
                witnesses
            );
        }
    }

    /**
     * @notice aggregates the digests of a given
     * subject.
     * @param subject The subject of which the credentials will be aggregate
     * @param digests The list of credentials' digests
     */
    function aggregateCredentials(
        Node storage self,
        address subject,
        bytes32[] memory digests
    ) public isInitialized(self) returns (bytes32) {
        return self.issuer.aggregateCredentials(subject, digests);
    }

    /**
     * @notice verifyCredentialRoot checks whether the root exists
     * and was correctly built based on the existent tree.
     * @param subject The subject of the credential tree
     * @param root The root to be checked.
     */
    function verifyCredentialRoot(
        Node storage self,
        address subject,
        bytes32 root
    ) public view isInitialized(self) returns (bool) {
        return self.issuer.verifyCredentialRoot(subject, root);
    }

    /**
     * @notice verifyCredentialTree performs a pre-order tree traversal over
     * the credential tree of a given subject and verifies if the given
     * root match with the current root on the root node and if all the
     * sub-trees were correctly built.
     * @param subject The subject of the credential tree
     */
    function verifyCredentialTree(Node storage self, address subject)
        public
        view
        isInitialized(self)
        returns (bool)
    {
        bytes32[] memory digests = self.issuer.getDigests(subject);
        assert(digests.length > 0);
        // Verify local root if exists
        if (self.issuer.hasRoot(subject)) {
            if (!self.issuer.verifyRootOf(subject, digests)) {
                return false;
            }
        }
        // Verify credential and potential subtrees
        for (uint256 i = 0; i < digests.length; i++) {
            // FIXME: use "ABIEncoderV2"
            // UnimplementedFeatureError: Encoding type "struct Notary.CredentialProof memory" not yet implemented.
            // Notary.CredentialProof memory c = _issuer.getCredentialProof(digests[i]);
            assert(self.issuer.recordExists(digests[i]));
            if (!self.issuer.verifyCredential(subject, digests[i])) {
                return false;
            }
            if (
                self.role == Role.Inner &&
                self.issuer.witnessesLength(digests[i]) > 0
            ) {
                if (
                    !_verifyCredentialNode(
                        self,
                        subject,
                        self.issuer.getEvidenceRoot(digests[i]),
                        self.issuer.getWitnesses(digests[i])
                    )
                ) {
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
        Node storage self,
        address subject,
        bytes32 croot,
        address[] memory witnesses
    ) private view returns (bool) {
        require(croot != bytes32(0), "Ctree/root cannot be null");
        bytes32[] memory proofs = new bytes32[](witnesses.length);
        for (uint256 i = 0; i < witnesses.length; i++) {
            address witnessesAddress = address(witnesses[i]);
            require(
                self.isChild[witnessesAddress],
                "Ctree/address not authorized"
            );
            NodeInterface node = NodeInterface(witnessesAddress);
            bool isNodeLike = ERC165Checker.supportsInterface(
                address(node),
                type(NodeInterface).interfaceId
            );
            assert(isNodeLike);
            if (node.isLeaf()) {
                proofs[i] = node.getRootProof(subject);
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
}
