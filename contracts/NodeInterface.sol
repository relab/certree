// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

interface NodeInterface {
    enum Role { Leaf, Inner }

    event NodeCreated(
        address indexed createdBy,
        address indexed nodeAddress,
        address[] owners,
        Role nodeRole
    );

    /**
     * @return true if the issuer contract is a leaf
     * false otherwise.
     */
    function isLeaf() external view returns(bool);

    /**
     * @return the address of the parent of this node.
     */
    function myParent() external view returns(address);

    /**
     * @return the node role.
     */
    function getRole() external view returns(Role);
}