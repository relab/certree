// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;
pragma experimental ABIEncoderV2;

import "./Notary.sol";

interface IssuerInterface {
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
    event CredentialSigned(
        address indexed signer,
        bytes32 indexed digest,
        uint256 signedBlock
    );

    /**
     * @notice confirms the emission of a quorum signed credential proof
     * @param digest The digest of the credential
     */
    function confirmCredential(bytes32 digest) external;

    /**
     * @notice registers a credential proof ensuring an append-only property
     * @param subject The subject of the credential
     * @param digest The digest of the credential
     * @param eRoot The resulted hash of all witnesses' roots
     * @param witnesses The list of all witnesses contracts
     */
    function registerCredential(
        address subject,
        bytes32 digest,
        bytes32 eRoot,
        address[] memory witnesses
    ) external;

    /**
     * @notice revokeCredential revokes a credential for a given reason
     * based on it's digest.
     * @param digest The digest of the credential
     * @param reason The hash of the reason of the revocation
     * @dev The reason should be publicaly available for anyone to inspect
     * i.e. Stored in a public swarm/ipfs address
     */
    function revokeCredential(bytes32 digest, bytes32 reason) external;

    /**
     * @notice aggregateCredentials aggregates the digests of a given
     * subject.
     * @param subject The subject of which the credentials will be aggregate
     * @param digests The list of credentials' digests
     */
    function aggregateCredentials(address subject, bytes32[] memory digests)
        external
        returns (bytes32);

    /**
     * @param subject The subject of the credential
     * @return the list of the registered digests of a subject
     */
    function getDigests(address subject)
        external
        view
        returns (bytes32[] memory);

    /**
     * @param digest The digest of the credential
     * @return the length of the witnesses of an issued credential proof
     */
    function witnessesLength(bytes32 digest) external view returns (uint256);

    /**
     * @param digest The digest of the credential
     * @return the witnesses of an issued credential proof
     */
    function getWitnesses(bytes32 digest)
        external
        view
        returns (address[] memory);

    /**
     * @param digest The digest of the credential
     * @return the root of the evidences of an issued credential proof.
     */
    function getEvidenceRoot(bytes32 digest) external view returns (bytes32);

    /**
     * @param subject The subject of the credential
     * @return the aggregated root of all credentials of a subject
     */
    function getRootProof(address subject) external view returns (bytes32);

    /**
     * @param digest The digest of the credential
     * @return the issued credential proof
     */
    function getCredentialProof(bytes32 digest)
        external
        view
        returns (Notary.CredentialProof memory);

    /**
     * @param digest The digest of the credential
     * @return the revoked credential proof
     */
    function getRevokedProof(bytes32 digest)
        external
        view
        returns (Notary.RevocationProof memory);

    /**
     * @notice check whether the root exists
     * @param subject The subject of the credential tree
     */
    function hasRoot(address subject) external view returns (bool);

    /**
     * @notice verifies the current root formation
     * @param subject The subject of the credential
     * @param digests The list of digests of the subject
     */
    function verifyRootOf(address subject, bytes32[] memory digests)
        external
        view
        returns (bool);

    /**
     * @notice verify if a credential proof was issued
     * @param digest The digest of the credential
     * @return true if an emission proof exists, false otherwise.
     */
    function recordExists(bytes32 digest) external view returns (bool);

    /**
     * @notice verify if a credential proof was revoked
     * @param digest The digest of the credential
     * @return true if a revocation exists, false otherwise.
     */
    function isRevoked(bytes32 digest) external view returns (bool);

    /**
     * @notice verify if a credential was signed by all parties
     * @param digest The digest of the credential to be verified
     */
    function isApproved(bytes32 digest) external view returns (bool);

    /**
     * @notice verifyCredential checks whether the credential is valid.
     * @dev A valid credential is the one signed by all parties and that
     * is not revoked.
     * @param subject The subject of the credential
     * @param digest The digest of the credential
     */
    function verifyCredential(address subject, bytes32 digest)
        external
        view
        returns (bool);

    /**
     * @notice verifyIssuedCredentials checks whether all credentials
     * of a given subject are valid.
     * @param subject The subject of the credential
     */
    function verifyIssuedCredentials(address subject)
        external
        view
        returns (bool);

    /**
     * @notice verifyCredentialRoot checks whether the root exists
     * and was correctly built based on the existent tree.
     * @param subject The subject of the credential tree
     * @param root The root to be checked.
     */
    function verifyCredentialRoot(address subject, bytes32 root)
        external
        view
        returns (bool);
}
