// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.8.0;

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
     * @return true if the issuer contract is a leaf
     */
    function isLeaf() external view returns(bool);

    /**
     * @return the registered digests of a subject
     */
    function digestsBySubject(address subject) external view returns (bytes32[] memory);

    /**
     * @return the aggregated proof of a subject
     */
    function getProof(address subject) external view returns (bytes32);

    /**
     * @return the witnesses of a proof
     */
    function getWitnesses(bytes32 digest) external view returns(address[] memory);

    /**
     * @dev isRevoked checks if the credential was revoked based on it's digest.
     */
    function isRevoked(bytes32 digest) external view returns (bool); //

    /**
     * @dev certified checks if a credential was signed by all parties.
     */
    function certified(bytes32 digest) external view returns (bool);

    /**
     * @dev certified registers the creation of a credential for
     * a particular subject
     */
    function registerCredential(address subject, bytes32 digest) external;

    /**
     * @dev confirmCredential confirms the agreement about the 
     * credential between the subject and the issuer.
     */
    function confirmCredential(bytes32 digest) external;

    /**
     * @dev revokeCredential revokes a credential for a given reason 
     * based on it's digest.
     */
    function revokeCredential(bytes32 digest, bytes32 reason) external;

    /**
     * @dev verifies if a list of digests are certified
     */
    function checkCredentials(bytes32[] calldata digests) external view returns (bool);

    /**
     * @dev aggregateCredentials perform an aggregation of all credentials
     * of a subject in the contract level. 
     */
    function aggregateCredentials(address subject) external returns (bytes32);

    /**
     * @dev verifyCredentialLeaf verifies if the credential of a given subject
     * was correctly generated based on the root contract
     */
    function verifyCredentialLeaf(address subject, bytes32 croot) external view returns (bool);
}
