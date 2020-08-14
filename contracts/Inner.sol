// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;
pragma experimental ABIEncoderV2;

import "./ERC165Checker.sol";
import "./CredentialSum.sol";
import "./Issuer.sol";
import "./Node.sol";
import "./Leaf.sol";
import "./NodeFactory.sol";
import "./Notary.sol";

//TODO: Remove nodes (require quorum)
contract Inner is Node, Issuer {

    constructor(address[] memory owners, uint256 quorum)
        Node(Role.Inner)
        Issuer(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function createChild(
        address[] memory owners,
        uint256 quorum,
        Role role
    ) public returns (address) {
        require(_role == Role.Inner, "Inner/Node must be Inner");

        if (role == Role.Leaf) {
            Leaf leaf = NodeFactory.createLeaf(owners, quorum);
            addNode(address(leaf));
            emit NodeCreated(
                msg.sender,
                address(leaf),
                owners,
                Role.Leaf
            );
            return address(leaf);
        }
        Inner inner = NodeFactory.createInner(owners, quorum);
        addNode(address(inner));
        emit NodeCreated(
            msg.sender,
            address(inner),
            owners,
            Role.Inner
        );
        return address(inner);
    }

    /**
     * @notice addNode adds a contract node to the certification tree.
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
    function addNode(address nodeAddress) internal {
        require(address(this) != nodeAddress, "Node/cannot add itself");
        require(!_children[nodeAddress], "Node/node already added");
        require(_role == Role.Inner, "Node/Leaves cannot have children");

        bool isIssuer = ERC165Checker.supportsInterface(nodeAddress, type(IssuerInterface).interfaceId);
        bool isNode = ERC165Checker.supportsInterface(nodeAddress, type(NodeInterface).interfaceId);
        assert(isIssuer && isNode);

        _children[nodeAddress] =  true;
        _childrenList.push(nodeAddress);
    }

    // Inner node logic
    function registerCredential(
        address subject,
        bytes32 digest,
        address[] memory witnesses // FIXME: the number of witnesses should be bounded to avoid gas limit on loops
    ) public onlyOwner {
        require(witnesses.length > 0, "Inner/witness not found");
        bytes32[] memory witenessProofs = new bytes32[](witnesses.length);
        for (uint256 i = 0; i < witnesses.length; i++) {
            address nodeAddress = address(witnesses[i]);
            require(_children[nodeAddress], "Inner/address not authorized");
            bool success = ERC165Checker.supportsInterface(nodeAddress, type(IssuerInterface).interfaceId);
            assert(success);
            Issuer issuer = Issuer(nodeAddress);
            bytes32 proof = issuer.getRootProof(subject); //TODO: check for re-entrancy
            // TODO: check the time of the creation of the roots on the witnesses? And only allow roots that have a order between them.
            // i.e. root[subject].insertedBlock and root[subject].blockTimestamp
            // Root should carry timestamp info
            require(proof != bytes32(0), "Inner/root not found");
            witenessProofs[i] = proof;
        }
        // FIXME: Not allow reuse of witness at same contract? keep a map of witnesses
        // FIXME: consider use sha256(abi.encodePacked(roots, digests));
        bytes32 evidencesRoot = CredentialSum.computeRoot(witenessProofs);
        _issue(subject, digest, evidencesRoot, witnesses);
        emit CredentialSigned(msg.sender, digest, block.number);
    }
    
    function registerCredential(address subject, bytes32 digest)
        public
        override
        onlyOwner
    {
        _issue(subject, digest, bytes32(0), new address[](0));
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    /**
     * @notice verifyCredential iteractivally verifies if a given credential
     * (i.e. represented by it's digest) corresponds to the aggregation 
     * of all stored credentials of a particular subject in all given sub-contracts
     * @param subject is the subject referred by all credentials to be verified
     * @param croot is the current credential root for the given subject
     * @param witnesses is an array with the address of all authorized
     * issuers that stores the subject sub-credentials
     */
    // TODO: certify that the methods exists on the witnesses contracts before
    // call them. i.e. the contract implements AccountableIssuerInterface
    function verifyCredentialNode(address subject, bytes32 croot, address[] memory witnesses) internal view returns(bool) {
        require(croot != bytes32(0), "Inner/root cannot be null");
        bytes32[] memory proofs = new bytes32[](witnesses.length);
        for (uint256 i = 0; i < witnesses.length; i++) {
            address witnessesAddress = address(witnesses[i]);
            require(_children[witnessesAddress], "Inner/address not authorized");
            Node node = Node(witnessesAddress);
            if (node.isLeaf()) {
                Leaf leaf = Leaf(witnessesAddress);
                proofs[i] = leaf.getRootProof(subject);
                if (!leaf.verifyCredentialRoot(subject, proofs[i])) {
                    return false;
                }
            } else {// witness is a node, check sub-tree
                Inner inner = Inner(witnessesAddress);
                if (!inner.verifyCredentialTree(subject)) {
                    return false;
                }
            }
        }
        return CredentialSum.verifyRoot(croot, proofs);
    }

    /**
     * @dev verifyCredentials performs a pre-order tree traversal over
     * the credential tree of a given subject and verifies if the given
     * root match with the current root on the root node and if all the 
     * sub-trees were correctly built.
     */
    function verifyCredentialTree(address subject) public view returns(bool) {
        bytes32[] memory digests = getDigests(subject);
        assert(digests.length > 0);
        // Verify local root if exists
        if (hasRoot(subject)) {
            if (!verifyRootOf(subject, digests)) {
                return false;
            }
        }
        // Verify credential and potential subtrees
        for (uint256 i = 0; i < digests.length; i++) {
            // FIXME: Solidity does not support this feature yet:
            // UnimplementedFeatureError: Encoding type "struct Notary.CredentialProof memory" not yet implemented.
            // Notary.CredentialProof memory c = issued(digests[i]);
            assert(isIssued(digests[i]));
            if (!super.verifyCredential(subject, digests[i])) {
                return false;
            }
            if(witnessesLength(digests[i]) > 0) {
                if (!verifyCredentialNode(subject, getEvidenceRoot(digests[i]), getWitnesses(digests[i]))){
                    return false;
                }
            }
        }
        return true;
    }
}