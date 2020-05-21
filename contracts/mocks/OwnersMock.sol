// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.7.0;

import "../Owners.sol";

contract OwnersMock is Owners {
    constructor(address[] memory owners, uint256 quorum)
        public
        Owners(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }
}
