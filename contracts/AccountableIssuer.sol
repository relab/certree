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
    address[] public issuers;

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
        Issuer(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    /**
     * @return the length of the issuers array
     */
    function issuersLength() public view returns (uint256) {
        return issuers.length;
    }

    function addIssuer(address issuerAddress) onlyOwner public {
        require(!isIssuer[issuerAddress], "AccountableIssuer: issuer already added");
        // TODO: check if is an issuer contract before add it?
        Issuer issuer = Issuer(issuerAddress);
        assert(address(issuer) == issuerAddress);
        isIssuer[issuerAddress] =  true;
        issuers.push(issuerAddress);
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
        bytes32 evidencesRoot = keccak256(abi.encode(roots));
        _issue(subject, digest, evidencesRoot, witnesses);
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    /**
     * @dev verifyCredential iteractivally verifies if a given credential
     * (i.e. represented by it's digest) corresponds to the aggregation 
     * of all stored credentials of a particular subject in all given sub-contracts
     * @param subject is the subject referred by all credentials to be verified
     * @param proofs is an array containing the resulted aggregated hashes of
     * all issuers in "witnesses"
     * @param witnesses is an array with the address of all authorized
     * issuers that stores the subject credentials
     */
    function verifyCredential(address subject, bytes32[] memory proofs, address[] memory witnesses) public view returns(bool) {
        require(witnesses.length > 0, "AccountableIssuer: require at least one issuer");
        for (uint256 i = 0; i < witnesses.length; i++) {
            address issuerAddress = address(witnesses[i]);
            require(isIssuer[issuerAddress], "AccountableIssuer: address not registered");
            Issuer issuer = Issuer(issuerAddress);
            //verify leaves construction
            if(!issuer.verifyCredential(subject, proofs[i])) { return false; }
        }
        return true;
    }
}
