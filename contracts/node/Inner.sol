// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "../ERC165Checker.sol";
import "../aggregator/CredentialSum.sol";
import "./Node.sol";
import "./Leaf.sol";

contract Inner is Node {

    constructor(address[] memory owners, uint8 quorum)
        Node(Role.Inner, owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
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
        // FIXME: the number of witnesses should be bounded to avoid gas limit on loops
    ) public onlyOwner isInitialized {
        require(witnesses.length > 0, "Inner/witness not found");
        bytes32[] memory witenessProofs = new bytes32[](witnesses.length);
        for (uint256 i = 0; i < witnesses.length; i++) {
            address nodeAddress = address(witnesses[i]);
            require(_children[nodeAddress], "Inner/address not authorized");
            bool success = ERC165Checker.supportsInterface(nodeAddress, type(IssuerInterface).interfaceId);
            assert(success);
            Issuer issuer = Issuer(nodeAddress);
            //TODO: check for re-entrancy
            bytes32 proof = issuer.getRootProof(subject);
            // TODO: check the time of the creation of the roots on the witnesses? And only allow roots that have a order between them.
            // i.e. root[subject].insertedBlock and root[subject].blockTimestamp
            require(proof != bytes32(0), "Inner/root not found");
            witenessProofs[i] = proof;
        }
        // FIXME: Not allow reuse of witness at same contract? keep a map of witnesses?
        // FIXME: consider use sha256(abi.encodePacked(roots, digests));
        bytes32 evidencesRoot = CredentialSum.computeRoot(witenessProofs);
        _issuer.register(subject, digest, evidencesRoot, witnesses);
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
        _issuer.register(subject, digest, bytes32(0), new address[](0));
    }

    /**
     * @notice verifyCredentials performs a pre-order tree traversal over
     * the credential tree of a given subject and verifies if the given
     * root match with the current root on the root node and if all the 
     * sub-trees were correctly built.
     * @param subject The subject of the credential tree
     */
    function verifyCredentialTree(address subject) public view returns(bool) {
        bytes32[] memory digests = _issuer.getDigests(subject);
        assert(digests.length > 0);
        // Verify local root if exists
        if (_issuer.hasRoot(subject)) {
            if (!_issuer.verifyRootOf(subject, digests)) {
                return false;
            }
        }
        // Verify credential and potential subtrees
        for (uint256 i = 0; i < digests.length; i++) {
            // FIXME: Solidity does not support this feature yet:
            // UnimplementedFeatureError: Encoding type "struct Notary.CredentialProof memory" not yet implemented.
            // Notary.CredentialProof memory c = issued(digests[i]);
            assert(_issuer.isIssued(digests[i]));
            if (!_issuer.verifyCredential(subject, digests[i])) {
                return false;
            }
            if(_issuer.witnessesLength(digests[i]) > 0) {
                if (!_verifyCredentialNode(subject, _issuer.getEvidenceRoot(digests[i]), _issuer.getWitnesses(digests[i]))){
                    return false;
                }
            }
        }
        return true;
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
    function _addNode(address nodeAddress) internal onlyOwner isInitialized {
        require(address(this) != nodeAddress, "Inner/cannot add itself");
        require(!_children[nodeAddress], "Inner/node already added");
        require(_role == Role.Inner, "Inner/Leaves cannot have children");

        bool isIssuer = ERC165Checker.supportsInterface(nodeAddress, type(IssuerInterface).interfaceId);
        bool isNode = ERC165Checker.supportsInterface(nodeAddress, type(NodeInterface).interfaceId);
        assert(isIssuer && isNode);

        _children[nodeAddress] =  true;
        _childrenList.push(nodeAddress);
    }

    //TODO: Remove nodes (require quorum)

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
    function _verifyCredentialNode(address subject, bytes32 croot, address[] memory witnesses) internal view returns(bool) {
        require(croot != bytes32(0), "Inner/root cannot be null");
        bytes32[] memory proofs = new bytes32[](witnesses.length);
        for (uint256 i = 0; i < witnesses.length; i++) {
            address witnessesAddress = address(witnesses[i]);
            require(_children[witnessesAddress], "Inner/address not authorized");
            Node node = Node(witnessesAddress);
            // TODO: certify that the methods exists on the witnesses contracts before call them (i.e. check interface implementation)
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
}