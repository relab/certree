// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "../node/Inner.sol";

contract InnerMock is Inner {

    constructor(address[] memory registrars, uint8 quorum)
        Inner(registrars, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
