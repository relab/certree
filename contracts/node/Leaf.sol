// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

import "./Node.sol";

contract Leaf is Node {

    constructor(address[] memory registrars, uint8 quorum)
        Node(Role.Leaf, registrars, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }
}