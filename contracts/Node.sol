// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;
pragma experimental ABIEncoderV2;

import "./ERC165Checker.sol";
import "./NodeInterface.sol";
// NodeFactory also imports Leaf and generate the following error on the Leaf contract:
// "Definition of base has to precede definition of derived contract"
// import "./NodeFactory.sol";

abstract contract Node is NodeInterface {
    address private _parent;

    Role internal _role = Role.Leaf;

    address[] internal _childrenList;
    
    mapping(address => bool) internal _children;

    constructor(Role role)
    {
        _parent = msg.sender; // if parent is a contract, then this instance is a leaf or internal node, otherwise parent is a external account address and this instance is the highest root contract.
        _role = role;
    }

    /**
     * @return true if the issuer contract is a leaf
     * false otherwise.
     */
    function isLeaf() public view override returns(bool) {
       return _role == Role.Leaf;
    }

    /**
     * @return the address of the parent of this node
     */
    function myParent() public view override returns(address) {
        return _parent;
    }

    /**
     * @return the node role.
     */
    function getRole() public view override returns(Role) {
        return _role;
    }
}