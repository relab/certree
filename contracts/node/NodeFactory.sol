// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "./Inner.sol";
import "./Leaf.sol";

library NodeFactory {
    function createLeaf(
        address[] memory owners,
        uint256 quorum
    ) public returns (Leaf) {
        return new Leaf(owners, quorum);
    }

    function createInner(
        address[] memory owners,
        uint256 quorum
    ) public returns (Inner) {
        return new Inner(owners, quorum);
    }
}
