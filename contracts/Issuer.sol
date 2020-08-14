// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;
pragma experimental ABIEncoderV2;

import "./ERC165.sol";
import "./IssuerInterface.sol";
import "./Owners.sol";
import "./CredentialSum.sol";
import "./Notary.sol";

// TODO: how to manage key changes? e.g. a student that lost his previous key. Reissue the certificates may not work, since the time ordering, thus a possible solution is the contract to store a key update information for the subject, or something like that.

/**
 * @title Issuer's contract ensures that verifiable credentials are correctly
 * issued by untrusted issuers, discouraging fraudulent processes by
 * establishing a casual order between the certificates.
 */
 // TODO: Allow upgradeable contract using similar approach of https://github.com/PeterBorah/ether-router
 abstract contract Issuer is IssuerInterface, Owners, ERC165 {
    using Notary for Notary.CredentialTree;
    Notary.CredentialTree private _tree;

    //TODO: define aggregator interface
    // Aggregator aggregator;
    using CredentialSum for CredentialSum.Root;
    mapping(address => CredentialSum.Root) public root;

    modifier notRevoked(bytes32 digest) {
        require(
            !isRevoked(digest),
            "Issuer/already revoked"
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
     * @return the issued credential proof
     */
    // function getIssuedProof(bytes32 digest)
    //     public
    //     view
    //     returns (Notary.CredentialProof memory)
    // {
    //     return _tree.issued[digest];
    // }

    // FIXME: Solidity does not support the feature above yet,
    // so we define some getter methods below.
    /**
     * @return the registered digests of a subject
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
     * @return the lenght of the witnesses of an issued credential proof
     */
    function witnessesLength(bytes32 digest) public view returns(uint256) {
        return _tree.issued[digest].witnesses.length;
    }

    /**
     * @return the witnesses of an issued credential proof
     */
    function getWitnesses(bytes32 digest) public view override returns(address[] memory){
        return _tree.issued[digest].witnesses;
    }

    /**
     * @return the root of the evidences of an issued credential proof.
     */
    function getEvidenceRoot(bytes32 digest) public view override returns (bytes32) {
        return _tree.issued[digest].evidencesRoot;
    }
    
    /**
     * @return the aggregated root of all credentials of a subject.
     * i.e. root of the credential tree in this contract instance
     */
    function getRootProof(address subject) public view override returns (bytes32) {
        return root[subject].proof;
    }

    /**
     * @notice verify if a credential proof was issued
     * @return true if an emission proof exists, false otherwise.
     */
    function isIssued(bytes32 digest) public view override returns (bool) {
        return _tree.isIssued(digest);
    }

    /**
     * @dev verify if a credential proof was revoked
     * @return true if a revocation exists, false otherwise.
     */
    function isRevoked(bytes32 digest) public view override returns (bool) {
        return _tree.isRevoked(digest);
    }

    function hasRoot(address subject)
        public
        view
        returns (bool)
    {
        return root[subject].hasRoot();
    }

    function verifyRootOf(address subject, bytes32[] memory digests)
        public
        view
        returns (bool)
    {
        return root[subject].verifySelfRoot(digests);
    }

    // TODO: check if subject isn't a contract address?
    // Use `extcodesize` can be tricky since it will also return 0 for the constructor method of a contract, but it seems that isn't a problem in this context, since it isn't being used to prevent any action.
    // TODO: improve the quorum check
    function _issue(address subject, bytes32 digest, bytes32 eRoot, address[] memory witnesses)
        internal
        onlyOwner
        notRevoked(digest)
    {
        require(!isOwner[subject], "Issuer/subject cannot be issuer");
        _tree.issue(subject, digest, eRoot, witnesses);
    }

    /**
     * @dev confirms the emission of a quorum signed credential proof
     */
    function confirmCredential(bytes32 digest) public override notRevoked(digest) {
        require(quorum() > 0,"Issuer/no quorum found");
        require(_tree.approve(digest, quorum()), "Issuer/approval failed");
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    /**
     * @dev Verify if a digest was already certified (i.e. signed by all parties)
     */
    function certified(bytes32 digest) public view override returns (bool) {
        return _tree.certified(digest);
    }

    /**
     * @dev revoke a credential proof
     */
    function revokeCredential(bytes32 digest, bytes32 reason)
        public
        override
        notRevoked(digest)
    {
        address subject = _tree.issued[digest].subject;
        require(isOwner[msg.sender] || subject == msg.sender, "Issuer/sender not authorized");
        // assert(_digestsBySubject[subject].length > 0);
        _tree.revoke(digest, reason);
        // TODO: analyse the consequence of deleting the proof.
        // delete issuedCredentials[digest];
        // TODO: emit events on the library?
        emit CredentialRevoked(
            digest,
            subject,
            msg.sender,
            block.number,
            reason
        );
    }

    /**
     * @dev aggregateCredentials aggregates the digests of a given subject on the credential level
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
        return root[subject].generateRoot(subject, _tree.digests[subject]);
    }

    // verify root aggregation
    function verifyCredentialRoot(address subject, bytes32 croot)
        public
        view
        override
        returns (bool)
    {
        require(root[subject].hasRoot(), "Issuer/root not found");
        require(
            _tree.digests[subject].length > 0,
            "Issuer/there are no credentials"
        );
        assert(root[subject].verifySelfRoot(_tree.digests[subject]));
        bytes32 proof = root[subject].proof;
        return proof == croot;
    }


    /**
     * @dev verifyAllCredentials
     */
    function verifyAllCredentials(address subject)
        public
        view
        override
        returns (bool)
    {
        require(
            _tree.digests[subject].length > 0,
            "Notary/there are no credentials"
        );
        // FIXME: restrict size of `digests` array
        for (uint256 i = 0; i < _tree.digests[subject].length; i++) {
            if (!verifyCredential(subject, _tree.digests[subject][i])) {
                return false;
            }
        }
        return true;
    }

    function verifyCredential(address subject, bytes32 digest)
        public
        view
        override
        returns (bool)
    {
        require(
            _tree.issued[digest].insertedBlock != 0,
            "Notary/credential not found"
        );
        require(
            _tree.issued[digest].subject == subject,
            "Notary/credential not owned by subject"
        );
        return (certified(digest) && isRevoked(digest));
    }
}
