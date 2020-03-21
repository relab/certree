pragma solidity >=0.5.13 <0.7.0;

/**
 * @title Owners contract
*/
contract Owners {
    // Map of owners
    mapping(address => bool) public isOwner;
    address[] public owners;

    // The required number of owners to authorize actions
    uint256 public quorum;

    // Logged when any owner change.
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    modifier onlyOwner {
        require(isOwner[msg.sender], "Owners: sender is not an owner");
        _;
    }

    /**
     * @dev Constructor
     * @param _owners is the array of all owners
     * @param _quorum is the required number of owners to perform actions
     */
    constructor(address[] memory _owners, uint256 _quorum) public {
        require(
            _owners.length > 0 && _owners.length < 256,
            "Owners: not enough owners"
        );
        require(
            _quorum > 0 && _quorum <= _owners.length,
            "Owners: quorum out of range"
        );
        for (uint256 i = 0; i < _owners.length; ++i) {
            // prevent duplicate and zero value address attack
            assert(!isOwner[_owners[i]] && _owners[i] != address(0));
            isOwner[_owners[i]] = true;
        }
        owners = _owners;
        quorum = _quorum;
    }

    /**
     * @dev OwnersLength
     * @return the length of the owners array
     */
    function ownersLength() public view returns (uint256) {
        return owners.length;
    }

    /**
     * @dev Change one of the owners
     * @param newOwner address of new owner
     */
    function changeOwner(address newOwner) public onlyOwner {
        require(owners.length > 0, "Owners: not enough owners");
        require(
            !isOwner[newOwner] && newOwner != address(0),
            "Owners: invalid address given"
        );
        address[] memory _owners = new address[](owners.length);
        // create a new array of owners replacing the old one
        for (uint256 i = 0; i < owners.length; ++i) {
            if (owners[i] != msg.sender) {
                _owners[i] = owners[i];
            } else {
                _owners[i] = newOwner;
            }
        }
        assert(_owners.length == quorum);
        emit OwnerChanged(msg.sender, newOwner);
        owners = _owners;
        isOwner[newOwner] = true;
        isOwner[msg.sender] = false;
    }
}
