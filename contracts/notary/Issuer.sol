// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "../Owners.sol";
import "../aggregator/CredentialSum.sol";
import "./Notary.sol";

/**
 * @title Issuer's contract ensures that verifiable credentials are correctly
 * issued by untrusted issuers, discouraging fraudulent processes by
 * establishing a casual order between the credential proofs.
 */
// TODO: Allow upgradeable contract using similar approach of https://github.com/PeterBorah/ether-router
// TODO: make issuer a library
abstract contract Issuer is Owners {
    using Notary for Notary.CredentialTree;
    Notary.CredentialTree internal _tree;

    //TODO: define aggregator interface
    // Aggregator aggregator;
    using CredentialSum for CredentialSum.Root;
    mapping(address => CredentialSum.Root) internal _root;

    // Logged when a credential is issued/created.
    event CredentialIssued(
        bytes32 indexed digest,
        address indexed subject,
        address indexed registrar,
        uint256 insertedBlock
    );

    // Logged when a credential is revoked by some owner.
    event CredentialRevoked(
        bytes32 indexed digest,
        address indexed subject,
        address indexed revoker,
        uint256 revokedBlock,
        bytes32 reason
    );

    // Logged when a credential is signed.
    event CredentialSigned(address indexed signer, bytes32 indexed digest, uint256 signedBlock);

    modifier notRevoked(bytes32 digest) {
        require(!isRevoked(digest), "Issuer/credential revoked");
        _;
    }

    modifier hasIssuedCredentials(address subject) {
        require(_tree.issued[subject].length > 0, "Issuer/there are no credentials");
        _;
    }

    constructor(address[] memory registrars, uint8 quorum) Owners(registrars, quorum) {
        // solhint-disable-previous-line no-empty-blocks
    }

    /**
     * @param subject The subject of the credential
     * @return the list of the issued credentials' digests of a subject
     */
    function getDigests(address subject) public view returns (bytes32[] memory) {
        return _tree.issued[subject];
    }

    /**
     * @param digest The digest of the credential
     * @return the registered credential proof
     */
    function getCredentialProof(bytes32 digest) public view returns (Notary.CredentialProof memory) {
        return _tree.getCredentialProof(digest);
    }

    /**
     * @param digest The digest of the credential
     * @return the revoked credential proof
     */
    function getRevokedProof(bytes32 digest) public view returns (Notary.RevocationProof memory) {
        return _tree.getRevokedProof(digest);
    }

    /**
     * @param digest The digest of the credential
     * @return the signers of a credential proof
     * @dev the returned array may contain zero addresses,
     * meaning that some of the owners did not signed the
     * credential yet.
     */
    function getCredentialSigners(bytes32 digest) public view returns (address[] memory) {
        address[] memory signers = new address[](_owners.length);
        uint256 index = 0;
        uint256 i = 0;
        for (; i < _owners.length; i++) {
            if (_tree.credentialSigners[digest][_owners[i]]) {
                signers[index] = _owners[i];
                index++;
            }
        }
        return signers;
    }

    /**
     * @notice verify if a credential proof was signed by a quorum
     * @param digest The digest of the credential
     */
    function isQuorumSigned(bytes32 digest) public view returns (bool) {
        return _tree.isQuorumSigned(digest, _quorum);
    }

    /**
     * @notice returns whether a credential proof was signed
     * by a registrar's account
     * @param digest The digest of the credential
     * @param account The registrar's account
     */
    function isSigned(bytes32 digest, address account) public view returns (bool) {
        return _tree.isSigned(digest, account);
    }

    /**
     * @param digest The digest of the credential
     * @return the length of the witnesses of an issued credential proof
     */
    function witnessesLength(bytes32 digest) public view returns (uint256) {
        return _tree.records[digest].witnesses.length;
    }

    /**
     * @param digest The digest of the credential
     * @return the witnesses of an issued credential proof
     */
    function getWitnesses(bytes32 digest) public view returns (address[] memory) {
        return _tree.records[digest].witnesses;
    }

    /**
     * @param digest The digest of the credential
     * @return the root of the evidences of an issued credential proof.
     */
    function getEvidenceRoot(bytes32 digest) public view returns (bytes32) {
        return _tree.records[digest].evidenceRoot;
    }

    /**
     * @param subject The subject of the credential
     * @return the aggregated root of all credentials of a subject
     */
    function _getRoot(address subject) internal view virtual returns (bytes32) {
        return _root[subject].proof;
    }

    /**
     * @param subject The subject of the credential
     * @return the root proof of a subject in this contract
     */
    // TODO: Implement it as a token?
    // TODO: Return an aggregator interface
    // TODO: Rename function
    function getProof(address subject) public view returns (CredentialSum.Root memory) {
        return _root[subject];
    }

    /**
     * @notice verify if a credential proof was created
     * @param digest The digest of the credential
     * @return true if an credential proof exists, false otherwise.
     */
    function recordExists(bytes32 digest) public view returns (bool) {
        return _tree.recordExists(digest);
    }

    /**
     * @notice verify if a credential proof was revoked
     * @param digest The digest of the credential
     * @return true if a revocation exists, false otherwise.
     */
    function isRevoked(bytes32 digest) public view returns (bool) {
        return _tree.isRevoked(digest);
    }

    /**
     * @notice check whether the root exists
     * @param subject The subject of the credential tree
     */
    function hasRoot(address subject) public view returns (bool) {
        return _root[subject].hasRoot();
    }

    /**
     * @notice perform an on-chain verification the current root formation
     * @param subject The subject of the credential
     * @param digests The list of digests of the subject
     */
    // TODO: limit the size of digests to avoid out-of-gas
    // TODO: specify implementation of verifier interface
    function verifyRootOf(address subject, bytes32[] memory digests) public view returns (bool) {
        return _root[subject].verifySelfRoot(digests);
    }

    /**
     * @notice approves the emission of a quorum signed credential proof
     * @param digest The digest of the credential
     */
    function _approveCredential(bytes32 digest) internal notRevoked(digest) {
        require(quorum() > 0, "Issuer/no quorum found");
        require(_tree._approve(digest, quorum()), "Issuer/approval failed");
    }

    /**
     * @notice verify if a credential was signed by all parties
     * @param digest The digest of the credential to be verified
     */
    function isApproved(bytes32 digest) public view returns (bool) {
        return _tree.isApproved(digest);
    }

    /**
     * @notice revokes a credential for a given reason
     * based on it's digest.
     * @param digest The digest of the credential
     * @param reason The hash of the reason of the revocation
     * @dev The reason should be publicaly available for anyone to inspect
     * i.e. Stored in a public swarm/ipfs address
     */
    // TODO: require quorum modifier
    function _revokeCredential(bytes32 digest, bytes32 reason) internal notRevoked(digest) {
        address subject = _tree.records[digest].subject;
        require(isOwner(msg.sender) || subject == msg.sender, "Issuer/sender not authorized");
        _tree._revoke(digest, reason);
    }

    /**
     * @notice aggregates the digests of a given
     * subject.
     * @param subject The subject of which the credentials will be aggregate
     * @param digests The list of credentials' digests
     */
    function _aggregateCredentials(address subject, bytes32[] memory digests)
        internal
        onlyOwner
        hasIssuedCredentials(subject)
        returns (bytes32)
    {
        // TODO: Alternatively, consider to hash the credential proofs instead of only the digests, i.e.: sha256(abi.encode(issuedCredentials[issued[i]]));
        // FIXME: the number of digests should be bounded to avoid gas limit on loops
        require(_tree._verifyProofs(subject, digests), "Issuer/has invalid credentials");
        return _root[subject].generateRoot(subject, digests);
    }

    /**
     * @notice checks whether the root exists
     * and was correctly built based on the existent tree.
     * @param subject The subject of the credential tree
     * @param root The root to be checked.
     */
    function _verifyCredentialRoot(address subject, bytes32 root)
        internal
        view
        hasIssuedCredentials(subject)
        returns (bool)
    {
        // Stored root must be derived from current digests of the subject
        return _root[subject].verifySelfRoot(_tree.issued[subject]) && _root[subject].proof == root;
    }

    /**
     * @notice verifyIssuedCredentials checks whether all credentials
     * of a given subject are valid.
     * @param subject The subject of the credential
     * @dev This function checks over all issued credentials if there is
     * any credentials there was not approved.
     */
    // TODO: Add period verification
    function verifyIssuedCredentials(address subject) public view hasIssuedCredentials(subject) returns (bool) {
        return _tree._verifyIssuedCredentials(subject);
    }

    /**
     * @notice verifyCredential checks whether the credential is valid.
     * @dev A valid credential is the one signed by all parties and that
     * is not revoked.
     * @param subject The subject of the credential
     * @param digest The digest of the credential
     */
    function verifyCredential(address subject, bytes32 digest) public view returns (bool) {
        return _tree._verifyCredential(subject, digest);
    }

    /**
     * @notice returns a list of revoked credentials
     * @param subject The subject that owns the credentials
     */
    function getRevoked(address subject) public view hasIssuedCredentials(subject) returns (bytes32[] memory) {
        bytes32[] memory revoked = new bytes32[](_tree.revokedCounter[subject]);
        uint256 index = 0;
        uint256 i = 0;
        for (; i < _tree.issued[subject].length; i++) {
            if (isRevoked(_tree.issued[subject][i])) {
                revoked[index] = _tree.issued[subject][i];
                index++;
            }
        }
        return revoked;
    }

    /**
     * @notice returns the number of revoked credentials for a subject
     * @param subject The subject that owns the credentials
     */
    function revokedCounter(address subject) public view returns (uint256) {
        return _tree.revokedCounter[subject];
    }

    /**
     * @notice registers a credential proof ensuring an append-only property
     * @param subject The subject of the credential
     * @param digest The digest of the credential
     * @param eRoot The resulted hash of all witnesses' roots
     * @param witnesses The list of all witnesses contracts
     */
    // TODO: check if subject isn't a contract address?
    // Use `extcodesize` can be tricky since it will also return 0 for the constructor method of a contract, but it seems that isn't a problem in this context, since it isn't being used to prevent any action.
    // TODO: improve the quorum check
    // FIXME: make issuer methods internal
    function _registerCredential(
        address subject,
        bytes32 digest,
        bytes32 eRoot,
        address[] memory witnesses
    ) internal onlyOwner notRevoked(digest) {
        require(!isOwner(subject), "Issuer/forbidden registrar");
        _tree._issue(subject, digest, eRoot, witnesses);
    }
}
