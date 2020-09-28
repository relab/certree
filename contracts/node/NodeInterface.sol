// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

enum Role {Leaf, Inner}

interface NodeInterface {
    event NodeAdded(
        address indexed createdBy,
        address indexed nodeAddress,
        address[] registrars,
        uint8 quorum,
        Role role
    );

    function initializeIssuer(address issuerAddress) external returns (bool);

    /**
     * @notice register a new credential without witnesses
     * @param subject The subject of the credential
     * @param digest The digest of the credential that is being created
     */
    function registerCredential(
        address subject,
        bytes32 digest,
        address[] memory witnesses
    ) external;

    /**
     * @notice aggregates the digests of a given
     * subject.
     * @param subject The subject of which the credentials will be aggregate
     * @param digests The list of credentials' digests
     */
    function aggregateCredentials(address subject, bytes32[] memory digests)
        external
        returns (bytes32);

    /**
     * @return the registered issuer contract
     */
    function issuer() external view returns (address);

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
    function getRootProof(address subject) external view returns (bytes32);

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

    /**
     * @notice verifyCredentialTree verifies if the credential tree
     * of the given subject is valid
     * @param subject The subject of the credential tree
     */
    function verifyCredentialTree(address subject) external view returns (bool);
}
