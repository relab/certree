// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

/**
 * @title Owners contract
*/
contract Owners {

    // The required number of owners to authorize actions
    uint8 internal _quorum;

    // Count the total number of owners
    uint8 internal _ownersCount;

    // Max number of owners
    uint8 private constant MAX_OWNERS = (2**8) - 1;

    // List of owners
    address[] internal _owners;

    // Map of owners
    mapping(address => bool) public isOwner;

    // Logged when any owner change.
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    modifier onlyOwner {
        require(isOwner[msg.sender], "Owners/sender is not an owner");
        _;
    }

    /**
     * @notice Constructor
     * @param ownersList is the array of all owners
     * @param quorumSize is the required number of owners to perform actions
     */
    constructor(address[] memory ownersList, uint8 quorumSize) {
        require(
            ownersList.length > 0 && ownersList.length <= MAX_OWNERS,
            "Owners/not enough owners"
        );
        require(
            quorumSize > 0 && quorumSize <= ownersList.length,
            "Owners/quorum out of range"
        );
        for (uint8 i = 0; i < ownersList.length; ++i) {
            // prevent duplicate and zero value address attack
            assert(!isOwner[ownersList[i]] && ownersList[i] != address(0x0));
            isOwner[ownersList[i]] = true;
        }
        _owners = ownersList;
        _ownersCount = uint8(ownersList.length);
        _quorum = quorumSize;
    }

    /**
     * @return the list of owners
     */
    function owners()
        public
        view
        returns (address[] memory)
    {
        return _owners;
    }

    /**
     * @return the quorum size
     */
    function quorum()
        public
        view
        returns (uint8)
    {
        return _quorum;
    }

    /**
     * @return the total number of owners
     */
    function ownersCount()
        public
        view
        returns (uint8)
    {
        return _ownersCount;
    }

    //FIXME: commented to remove cost
    /**
     * @notice Change one of the owners
     * @param newOwner address of new owner
     */
    function changeOwner(address newOwner) public onlyOwner {
        require(
            !isOwner[newOwner] && newOwner != address(0x0),
            "Owners/invalid address given"
        );
        // Owners should never be empty
        assert(_owners.length > 0 && _owners.length <= MAX_OWNERS);
        address[] memory ownersList = new address[](_owners.length);
        // create a new array of owners replacing the old one
        for (uint8 i = 0; i < _owners.length; ++i) {
            if (_owners[i] != msg.sender) {
                ownersList[i] = _owners[i];
            } else {
                ownersList[i] = newOwner;
            }
        }
        // The quorum size should never change
        assert(ownersList.length == _quorum);
        emit OwnerChanged(msg.sender, newOwner);
        _owners = ownersList;
        isOwner[newOwner] = true;
        isOwner[msg.sender] = false;
    }

    // TODO: add and remove owners
}
