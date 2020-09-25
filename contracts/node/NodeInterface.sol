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

    function initializeIssuer() external;

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
}

interface LeafInterface {
    function registerCredential(address subject, bytes32 digest) external;
}

interface InnerInterface {
    function registerCredential(
        address subject,
        bytes32 digest,
        address[] memory witnesses
    ) external;

    function addChild(address node, Role role) external returns (address);

    function registerCredential(address subject, bytes32 digest) external;

    function verifyCredentialTree(address subject) external view returns (bool);
}
