// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

enum Role {Leaf, Inner}

interface NodeInterface {
    event NodeAdded(
        address indexed createdBy,
        address indexed nodeAddress,
        Role role
    );

    /**
     * @notice create a new node on the certification tree
     * @dev The new node can be a Leaf or a Inner node.
     * @param nodeAddress The address of the node
     */
    function addChild(address nodeAddress) external;

    /**
     * @return true if the issuer contract is a leaf false otherwise.
     */
    function isLeaf() external view returns (bool);

    /**
     * @return the address of the parent of this node.
     */
    function myParent() external view returns (address);

    /**
     * @return the node role.
     */
    function getRole() external view returns (Role);

    /**
     * @param subject The subject of the credential
     * @return the aggregated root of all credentials of a subject
     */
    function getRoot(address subject) external view returns (bytes32);

    /**
     * @notice verifyCredentialTree verifies if the credential tree
     * of the given subject is valid
     * @param subject The subject of the credential tree
     */
    function verifyCredentialTree(address subject) external view returns (bool);

    /**
     * @notice checks whether the root exists
     * and was correctly built based on the existent tree.
     * @param subject The subject of the credential tree
     * @param root The root to be checked.
     */
    function verifyCredentialRoot(address subject, bytes32 root)
        external
        view
        returns (bool);

    /**
     * @notice approves the emission of a quorum signed credential proof
     * @param digest The digest of the credential
     */
    function approveCredential(bytes32 digest) external;

    /**
     * @notice registers a credential proof ensuring an append-only property
     * @param subject The subject of the credential
     * @param digest The digest of the credential
     * @param witnesses The list of all witnesses contracts
     */
    function registerCredential(
        address subject,
        bytes32 digest,
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
}
