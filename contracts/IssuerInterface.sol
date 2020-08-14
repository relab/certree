// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;
pragma experimental ABIEncoderV2;

interface IssuerInterface {
    // Logged when a credential is issued/created.
    event CredentialIssued(
        bytes32 indexed digest,
        address indexed subject,
        address indexed issuer,
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
     * @return the registered digests of a subject
     */
    function getDigests(address subject) external view returns (bytes32[] memory);

    /**
     * @return the witnesses of an issued credential proof
     */
    function getWitnesses(bytes32 digest) external view returns(address[] memory);

    /**
     * @return the root of the evidences of an issued credential proof.
     */
    function getEvidenceRoot(bytes32 digest) external view returns (bytes32);

     /**
     * @return the aggregated root of all credentials of a subject.
     * i.e. root of the credential tree in this contract instance
     */
    function getRootProof(address subject) external view returns (bytes32);

    /**
     * @notice isIssued checks if the credential was issued based on it's digest.
     */
    function isIssued(bytes32 digest) external view returns (bool);

    /**
     * @notice isRevoked checks if the credential was revoked based on it's digest.
     */
    function isRevoked(bytes32 digest) external view returns (bool);

    /**
     * @notice certified checks if a credential was signed by all parties.
     */
    function certified(bytes32 digest) external view returns (bool);

    /**
     * @notice certified registers the creation of a credential for
     * a particular subject
     */
    function registerCredential(address subject, bytes32 digest) external;

    /**
     * @notice confirmCredential confirms the agreement about the 
     * credential between the subject and the issuer.
     */
    function confirmCredential(bytes32 digest) external;

    /**
     * @notice revokeCredential revokes a credential for a given reason 
     * based on it's digest.
     */
    function revokeCredential(bytes32 digest, bytes32 reason) external;

    /**
     * @notice aggregateCredentials perform an aggregation of all credentials
     * of a subject in the contract level. 
     */
    function aggregateCredentials(address subject) external returns (bytes32);

    /**
     * @notice verifyCredential verifies if the credential of a given subject
     * was correctly issued
     */
    function verifyCredential(address subject, bytes32 digest) external view returns (bool);

    /**
     * @notice verifyAllCredentials verifies if all credentials of a given subject
     * were correctly issued
     */
    function verifyAllCredentials(address subject) external view returns (bool);

    /**
     * @notice verifyCredentialRoot
     */
    function verifyCredentialRoot(address subject, bytes32 croot)
        external
        view
        returns (bool);
}
