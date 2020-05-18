// SPDX-License-Identifier: MIT
pragma solidity >=0.5.13 <0.7.0;
// pragma experimental ABIEncoderV2;

import "./Issuer.sol";
import "./CredentialSum.sol";
// import "@openzeppelin/contracts/math/SafeMath.sol";
// import "@openzeppelin/contracts/cryptography/ECDSA.sol";

/**
 * @title AccountableIssuer's contract
 * This contract act as a factory contract for issuers and
 * consider implicit signatures verification already necessary
 * to perform valid transactions.
 * TODO Implement using EIP712:
 * https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md
 */
abstract contract AccountableIssuer is Issuer {
    address[] private _issuers;

    // Map of all issuers sub-contracts
    mapping(address => bool) public isIssuer;

    // Logged when an issuer added.
    event IssuerAdded(
        address indexed issuerAddress,
        address indexed addedBy
    );

    //TODO: blacklist issuers?

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

    function addIssuer(address issuerAddress) onlyOwner public {
        require(!isIssuer[issuerAddress], "AccountableIssuer: issuer already added");
        // TODO: check if is an issuer contract before add it?
        Issuer issuer = Issuer(issuerAddress);
        assert(address(issuer) == issuerAddress);
        isIssuer[issuerAddress] =  true;
        _issuers.push(issuerAddress);
        emit IssuerAdded(issuerAddress, msg.sender);
    }

    /**
     * @dev registerCredential collects all subject's credentials and issue a
     * new credential proof iff the aggregation of those credentials on
     * the sub-contracts match the given root (i.e. off-chain aggregation == on-chain aggregation)
     */
    function registerCredential(
        address subject,
        bytes32 digest,
        address[] memory witnesses
    ) public onlyOwner {
        require(witnesses.length > 0, "AccountableIssuer: require at least one issuer");
        bytes32[] memory roots = new bytes32[](witnesses.length);
        for (uint256 i = 0; i < witnesses.length; i++) {
            address issuerAddress = address(witnesses[i]);
            require(isIssuer[issuerAddress], "AccountableIssuer: issuer's address doesn't found");
            Issuer issuer = Issuer(issuerAddress);
            bytes32 root = issuer.getProof(subject);
            require(root != bytes32(0), "AccountableIssuer: aggregation on sub-contract not found");
            roots[i] = root;
        }
        // FIXME: consider use sha256(abi.encodePacked(roots, digests));
        bytes32 evidencesRoot = CredentialSum.makeRoot(roots);
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
    function verifyCredentialNode(address subject, bytes32 croot, address[] memory witnesses) internal view returns(bool) {
        require(croot != bytes32(0), "AccountableIssuer: root cannot be null");
        bytes32[] memory proofs = new bytes32[](witnesses.length);
        for (uint256 i = 0; i < witnesses.length; i++) {
            address witnessesAddress = address(witnesses[i]);
            require(isIssuer[witnessesAddress], "AccountableIssuer: witnesses address not authorized");
            Issuer leaf = Issuer(witnessesAddress);
            proofs[i] = leaf.getProof(subject);
            if (leaf.isLeaf()) { // witness is a leaf, check all credentials
                if (!leaf.verifyCredentialLeaf(subject, proofs[i])) {
                    return false;
                }
            } else { // witness is a node, check sub-tree
                AccountableIssuer node = AccountableIssuer(witnessesAddress);
                if (!node.verifyCredentialTree(subject, proofs[i])) {
                    return false;
                }
            }
        }
        return CredentialSum.verifyProof(croot, proofs);
    }

    /**
     * @dev verifyCredentials performs a pre-order tree traversal over
     * the credential tree of a given subject and verifies if the given
     * root match with the current root on the root node and if all the 
     * sub-trees were correctly built.
     */
    function verifyCredentialTree(address subject, bytes32 croot) public view returns(bool) {
        require(croot != bytes32(0), "AccountableIssuer: certification period didn't finish yet");
        if (!super.verifyCredentialLeaf(subject, croot)) {
            return false;
        }
        bytes32[] memory digests = digestsBySubject(subject);
        require(digests.length > 0, "AccountableIssuer: there is no credential to be verified");
        // Assumes that nodes cannot have credential proofs without at least one witness.
        for (uint256 i = 0; i < digests.length; i++) {
            CredentialProof memory c = issuedCredentials[digests[i]];
            assert(c.insertedBlock != 0); // credentials must exist
            if(c.witnesses.length > 0) {
                if (!verifyCredentialNode(subject, c.evidencesRoot, c.witnesses)){
                    return false;
                }
            }
        }
        return true;
    }
}
