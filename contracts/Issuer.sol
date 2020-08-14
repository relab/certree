// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;
// pragma experimental ABIEncoderV2;

import "./ERC165.sol";
import "./IssuerInterface.sol";
import "./Owners.sol";
import "./CredentialSum.sol";
import "./Notary.sol";

/**
 * @title Issuer's contract ensures that verifiable credentials are correctly
 * issued by untrusted issuers, discouraging fraudulent processes by
 * establishing a casual order between the credential proofs.
 */
 // TODO: Allow upgradeable contract using similar approach of https://github.com/PeterBorah/ether-router
 abstract contract Issuer is IssuerInterface, Owners, ERC165 {
    using Notary for Notary.CredentialTree;
    Notary.CredentialTree private _tree;

    //TODO: define aggregator interface
    // Aggregator aggregator;
    using CredentialSum for CredentialSum.Root;
    mapping(address => CredentialSum.Root) private _root;

    modifier notRevoked(bytes32 digest) {
        require(
            !isRevoked(digest),
            "Issuer/already revoked"
        );
        _;
    }

    modifier existsCredentials(address subject) {
        require(
            _tree.digests[subject].length > 0,
            "Issuer/there are no credentials"
        );
        _;
    }

    constructor(address[] memory owners, uint256 quorum)
        Owners(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function supportsInterface(bytes4 interfaceId) override external pure returns (bool) {
        return interfaceId == type(ERC165).interfaceId || interfaceId == type(IssuerInterface).interfaceId;
    }

    /**
     * @param subject The subject of the credential
     * @return the list of the registered digests of a subject
     */
    function getDigests(address subject)
        public
        view
        override
        returns (bytes32[] memory)
    {
        return _tree.digests[subject];
    }

    /**
     * @param digest The digest of the credential
     * @return the lenght of the witnesses of an issued credential proof
     */
    function witnessesLength(bytes32 digest) public view returns(uint256) {
        return _tree.issued[digest].witnesses.length;
    }

    /**
     * @param digest The digest of the credential
     * @return the witnesses of an issued credential proof
     */
    function getWitnesses(bytes32 digest) public view override returns(address[] memory){
        return _tree.issued[digest].witnesses;
    }

    /**
     * @param digest The digest of the credential
     * @return the root of the evidences of an issued credential proof.
     */
    function getEvidenceRoot(bytes32 digest) public view override returns (bytes32) {
        return _tree.issued[digest].evidencesRoot;
    }
    
    /**
     * @param subject The subject of the credential
     * @return the aggregated root of all credentials of a subject
     */
    function getRootProof(address subject) public view override returns (bytes32) {
        return _root[subject].proof;
    }

    /**
     * @notice verify if a credential proof was issued
     * @param digest The digest of the credential
     * @return true if an emission proof exists, false otherwise.
     */
    function isIssued(bytes32 digest) public view override returns (bool) {
        return _tree.isIssued(digest);
    }

    /**
     * @notice verify if a credential proof was revoked
     * @param digest The digest of the credential
     * @return true if a revocation exists, false otherwise.
     */
    function isRevoked(bytes32 digest) public view override returns (bool) {
        return _tree.isRevoked(digest);
    }

    /**
     * @notice check whether the root exists
     * @param subject The subject of the credential tree
     */
    function hasRoot(address subject) public view returns (bool)
    {
        return _root[subject].hasRoot();
    }

    /**
     * @notice verifies the current root formation
     * @param subject The subject of the credential
     * @param digests The list of digests of the subject
     */
    function verifyRootOf(address subject, bytes32[] memory digests)
        public
        view
        returns (bool)
    {
        return _root[subject].verifySelfRoot(digests);
    }

    /**
     * @notice confirms the emission of a quorum signed credential proof
     * @param digest The digest of the credential
     */
    function confirmCredential(bytes32 digest) public override notRevoked(digest) {
        require(quorum() > 0,"Issuer/no quorum found");
        require(_tree._approve(digest, quorum()), "Issuer/approval failed");
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    /**
     * @notice verify if a credential was signed by all parties
     * @param digest The digest of the credential to be verified
     */
    function certified(bytes32 digest) public view override returns (bool) {
        return _tree.certified(digest);
    }

    /**
     * @notice revokeCredential revokes a credential for a given reason
     * based on it's digest.
     * @param digest The digest of the credential
     * @param reason The hash of the reason of the revocation
     * @dev The reason should be publicaly available for anyone to inspect
     * i.e. Stored in a public swarm/ipfs address
     */
    function revokeCredential(bytes32 digest, bytes32 reason)
        public
        override
        notRevoked(digest)
    {
        address subject = _tree.issued[digest].subject;
        require(isOwner[msg.sender] || subject == msg.sender, "Issuer/sender not authorized");
        _tree._revoke(digest, reason);
        // TODO: emit events on the library instead?
        emit CredentialRevoked(
            digest,
            subject,
            msg.sender,
            block.number,
            reason
        );
    }

    /**
     * @notice aggregateCredentials aggregates the digests of a given
     * subject.
     * @param subject The subject of which the credentials will be aggregate
     */
    function aggregateCredentials(address subject)
        public
        virtual
        override
        onlyOwner
        returns (bytes32)
    {
        // TODO: Alternativaly, consider to hash the credential proofs instead of only the digests, i.e.: sha256(abi.encode(issuedCredentials[digests[i]]));
        // FIXME: the number of digests should be bounded to avoid gas limit on loops
        require(
            verifyAllCredentials(subject),
            "Issuer/there are unsigned credentials"
        );
        return _root[subject].generateRoot(subject, _tree.digests[subject]);
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
        override
        existsCredentials(subject)
        returns (bool)
    {
        require(_root[subject].hasRoot(), "Issuer/root not found");
        // Stored root must be derived from current digests of the subject
        assert(_root[subject].verifySelfRoot(_tree.digests[subject]));
        bytes32 proof = _root[subject].proof;
        return proof == root;
    }

    /**
     * @notice verifyAllCredentials checks whether all credentials
     * of a given subject are valid.
     * @param subject The subject of the credential
     */
    // TODO: Add period verification
    function verifyAllCredentials(address subject)
        public
        view
        override
        existsCredentials(subject)
        returns (bool)
    {
        // FIXME: restrict size of `digests` array
        for (uint256 i = 0; i < _tree.digests[subject].length; i++) {
            if (!verifyCredential(subject, _tree.digests[subject][i])) {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice verifyCredential checks whether the credential is valid.
     * @dev A valid credential is the one signed by all parties and that
     * is not revoked.
     * @param subject The subject of the credential
     * @param digest The digest of the credential
     */
    function verifyCredential(address subject, bytes32 digest)
        public
        view
        override
        returns (bool)
    {
        require(
            _tree.issued[digest].insertedBlock != 0,
            "Issuer/credential not found"
        );
        require(
            _tree.issued[digest].subject == subject,
            "Issuer/credential not owned by subject"
        );
        return (certified(digest) && isRevoked(digest));
    }

    /**
     * @notice register a credential proof ensuring an append-only property
     * @param subject The subject of the credential
     * @param digest The digest of the credential
     * @param eRoot The resulted hash of all witnesses' roots
     * @param witnesses The list of all witnesses contracts
     */
    // TODO: check if subject isn't a contract address?
    // Use `extcodesize` can be tricky since it will also return 0 for the constructor method of a contract, but it seems that isn't a problem in this context, since it isn't being used to prevent any action.
    // TODO: improve the quorum check
    function _register(address subject, bytes32 digest, bytes32 eRoot, address[] memory witnesses)
        internal
        onlyOwner
        notRevoked(digest)
    {
        require(!isOwner[subject], "Issuer/subject cannot be the issuer");
        _tree._issue(subject, digest, eRoot, witnesses);
    }
}
