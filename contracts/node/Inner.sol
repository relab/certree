// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "./Node.sol";

contract Inner is Node {
    constructor(address[] memory registrars, uint8 quorum) Node(Role.Inner, registrars, quorum) {
        // solhint-disable-previous-line no-empty-blocks
    }
}
