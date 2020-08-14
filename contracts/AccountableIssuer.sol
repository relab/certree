// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.8.0;
pragma experimental ABIEncoderV2;

import "./ERC165.sol";
import "./ERC165Checker.sol";
import "./IssuerInterface.sol";
import "./Issuer.sol";
import "./CredentialSum.sol";

/**
 * @title AccountableIssuer's contract
 * This contract act as a factory contract for issuers and
 * consider implicit signatures verification already necessary
 * to perform valid transactions.
 *
 * TODO: - Implement using EIP712:
 * https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md
 *       - Convert Issuer and AccountableIssuer to libraries
 */

// FIXME: Contract creation initialization returns data with length of more than 24576 bytes. The deployment will likely fails.
// Move issuer functions to library.
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-170.md
abstract contract AccountableIssuer is Issuer {
    using CredentialSum for CredentialSum.Root;

    address[] private _issuers;

    // Map of all issuers sub-contracts
    mapping(address => bool) public authorizedIssuers;

    // TODO: replace the above fields by a _issuers map
    // mapping(address => IssuerInterface) public _issuers;

    // Logged when an issuer added.
    event IssuerAdded(
        address indexed issuerAddress,
        address indexed addedBy
    );

    constructor(address[] memory owners, uint256 quorum)
        public
        Issuer(owners, quorum, false)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    /**
     * @return the length of the issuers array
     */
    function issuersLength() public view returns (uint256) {
        return _issuers.length;
    }

    /**
     * @return the list of issuers
     */
    function issuers()
        public
        view
        returns (address[] memory)
    {
        return _issuers;
    }

    /**
     * @dev addIssuer adds a contract as an issuer.
     * This function checks if the account address implements the
     * IssuerInterfaces, but this isn't sufficient to ensure the
     * correctness of the implementation itself.
     * Malicious contracts that match the IssuerInterface can still
     * be added and further checks of the contract code should be
     * performed before approval of the inclusion.
     */
    // FIXME: - require a quorum of owners
    //        - not allow add issuer where the sender is an owner
    //        - this function allows cycles, and there is no easy
    // way to detect it other than going through all children of `issuerAddress` and checking if any reference this.
    // Consider remove this function and move to concrete Issuer
    // implementations/library, making the AccountableIssuer
    // create them instead of add any implementer.
    // TODO: factory methods to create accountableIssuers and Issuers
    function addIssuer(address issuerAddress) public onlyOwner {
        require(address(this) != issuerAddress, "AccountableIssuer: cannot add itself");
        require(!authorizedIssuers[issuerAddress], "AccountableIssuer: issuer already added");
        bool success = ERC165Checker.supportsInterface(issuerAddress, type(IssuerInterface).interfaceId);
        assert(success);
        authorizedIssuers[issuerAddress] =  true;
        _issuers.push(issuerAddress);
        emit IssuerAdded(issuerAddress, msg.sender);
    }

    /**
     * @dev registerCredential collects all subject's credentials and issue a
     * new credential proof iff the aggregation of those credentials on
     * the sub-contracts match the given root (i.e. off-chain aggregation == on-chain aggregation)
     */
    // TODO: onlyQuorum
    function registerCredential(
        address subject,
        bytes32 digest,
        address[] memory witnesses // FIXME: the number of witnesses should be bounded to avoid gas limit on loops
    ) public onlyOwner {
        require(witnesses.length > 0, "AccountableIssuer: require at least one issuer");
        bytes32[] memory witenessProofs = new bytes32[](witnesses.length);
        for (uint256 i = 0; i < witnesses.length; i++) {
            address issuerAddress = address(witnesses[i]);
            require(authorizedIssuers[issuerAddress], "AccountableIssuer: issuer's address doesn't found");
            bool success = ERC165Checker.supportsInterface(issuerAddress, type(IssuerInterface).interfaceId);
            assert(success);
            Issuer issuer = Issuer(issuerAddress);
            bytes32 proof = issuer.getRootProof(subject); //TODO: check for re-entrancy
            // TODO: check the time of the creation of the roots on the witnesses? And only allow roots that have a order between them.
            // i.e. root[subject].insertedBlock and root[subject].blockTimestamp
            // Root should carry timestamp info
            require(proof != bytes32(0), "AccountableIssuer: aggregation on sub-contract not found");
            witenessProofs[i] = proof;
        }
        // FIXME: Not allow reuse of witness at same contract? keep a map of witnesses
        // FIXME: consider use sha256(abi.encodePacked(roots, digests));
        bytes32 evidencesRoot = CredentialSum.computeRoot(witenessProofs);
        _issue(subject, digest, evidencesRoot, witnesses);
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    /**
     * @dev verifyCredential iteractivally verifies if a given credential
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
        require(croot != bytes32(0), "AccountableIssuer: root cannot be null");
        bytes32[] memory proofs = new bytes32[](witnesses.length);
        for (uint256 i = 0; i < witnesses.length; i++) {
            address witnessesAddress = address(witnesses[i]);
            require(authorizedIssuers[witnessesAddress], "AccountableIssuer: witnesses address not authorized");
            Issuer leaf = Issuer(witnessesAddress);
            proofs[i] = leaf.getRootProof(subject);
            if (!leaf.verifyCredentialRoot(subject, proofs[i])) {
                return false;
            }
            if (!leaf.isLeaf()) { // witness is a node, check sub-tree
                AccountableIssuer node = AccountableIssuer(witnessesAddress);
                if (!node.verifyCredentialTree(subject)) {
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
        bytes32[] memory digests = digestsBySubject(subject);
        assert(digests.length > 0);
        // Verify local root if exists
        if (root[subject].hasRoot()) {
            if (!root[subject].verifySelfRoot(digests)) {
                return false;
            }
        }
        // Verify credential and potential subtrees
        for (uint256 i = 0; i < digests.length; i++) {
            CredentialProof memory c = issuedCredentials[digests[i]];
            assert(c.digest == digests[i]);
            if (!super.verifyCredential(subject, digests[i])) {
                return false;
            }
            if(c.witnesses.length > 0) {
                if (!verifyCredentialNode(subject, c.evidencesRoot, c.witnesses)){
                    return false;
                }
            }
        }
        return true;
    }
}
