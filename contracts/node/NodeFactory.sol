// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "./Inner.sol";
import "./Leaf.sol";

contract NodeFactory is Inner {

    constructor(address[] memory owners, uint256 quorum)
        Inner(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function createLeaf(
        address[] memory owners,
        uint256 quorum
    ) internal returns (Leaf) {
        return new Leaf(owners, quorum);
    }

    function createInner(
        address[] memory owners,
        uint256 quorum
    ) internal returns (Inner) {
        return new Inner(owners, quorum);
    }

    /**
     * @notice create a new node on the certification tree
     * @dev The new node can be a Leaf or a Inner node.
     * @param owners The list of owners of the new node
     * @param quorum The quorum of signatures required to perform actions
     * in the new node
     * @param role The role of the node (i.e. Leaf or Inner)
     */
    function createChild(
        address[] memory owners,
        uint256 quorum,
        Role role
    ) public returns (address) {
        require(_role == Role.Inner, "NodeFactory/Node must be Inner");

        if (role == Role.Leaf) {
            Leaf leaf = createLeaf(owners, quorum);
            _addNode(address(leaf));
            emit NodeCreated(
                msg.sender,
                address(leaf),
                owners,
                quorum,
                Role.Leaf
            );
            return address(leaf);
        }
        Inner inner = createInner(owners, quorum);
        _addNode(address(inner));
        emit NodeCreated(
            msg.sender,
            address(inner),
            owners,
            quorum,
            Role.Inner
        );
        return address(inner);
    }
}
