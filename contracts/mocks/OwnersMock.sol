// SPDX-License-Identifier: MIT
pragma solidity >=0.5.13 <0.7.0;

import "../Owners.sol";

contract OwnersMock is Owners {
    constructor(address[] memory owners, uint256 quorum)
        public
        Owners(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function setOwner(address owner) public {
        owners.push(owner);
        isOwner[owner] = true;
    }

    function resetOwners() public {
        for (uint256 i = 0; i < owners.length; ++i) {
            isOwner[owners[i]] = false;
        }
        delete owners;
    }

    function deleteOwners() public {
        delete owners;
    }
}
