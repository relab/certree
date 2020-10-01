// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "../notary/IssuerInterface.sol";

enum Role {Leaf, Inner}

interface NodeInterface {
    event NodeAdded(
        address indexed createdBy,
        address indexed nodeAddress,
        address[] registrars,
        uint8 quorum,
        Role role
    );

    /**
     * @notice create a new node on the certification tree
     * @dev The new node can be a Leaf or a Inner node.
     * @param nodeAddress The address of the node
     */
    function addChild(address nodeAddress) external returns (address);

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
