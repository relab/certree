// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

// TODO: Use AggregatorInterface
import "./CredentialSum.sol";

interface IssuerInterface {
    /**
     * @dev CredentialProof represents an on-chain proof that a
     * verifiable credential was created and signed by an issuer.
     */
    struct CredentialProof {
        uint256 signed; // Amount of owners who signed
        bool approved; // Whether the subject approved the credential
        uint256 insertedBlock; // The block number of the proof creation
        uint256 blockTimestamp; // The block timestamp of the proof creation
        uint256 nonce; // Increment-only counter of credentials of the same subject
        address issuer; // The issuer address of this proof
        address subject; // The entity address refered by a proof
        bytes32 digest; // The digest of the credential stored (e.g. Swarm/IPFS hash)
        bytes32 evidencesRoot; // if is a leaf root is zero otherwise is the result of the aggregation of the digests at the witnesses
        address[] witnesses; // if witnesses is empty is a leaf notary, otherwise is a list of node notaries
    }

    /**
     * @dev RevocationProof represents an on-chain proof that a
     * verifiable credential was revoked by an issuer.
     */
    struct RevocationProof {
        address issuer;
        address subject;
        uint256 revokedBlock; // The block number of the revocation (0 if not revoked)
        bytes32 reason; // digest of the reason of the revocation
    }

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
    function getRootProof(address subject) external view returns (bytes32);

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
     * @dev aggregateCredentials perform an aggregation of all credentials
     * of a subject in the contract level. 
     */
    function aggregateCredentials(address subject) external returns (bytes32);

    /**
     * @dev verifyCredential verifies if the credential of a given subject
     * was correctly issued
     */
    function verifyCredential(address subject, bytes32 digest) external view returns (bool);

    /**
     * @dev verifyAllCredentials verifies if all credentials of a given subject
     * were correctly issued
     */
    function verifyAllCredentials(address subject) external view returns (bool);

    /**
     * @dev verifyCredentialRoot
     */
    function verifyCredentialRoot(address subject, bytes32 croot)
        external
        view
        returns (bool);
}
