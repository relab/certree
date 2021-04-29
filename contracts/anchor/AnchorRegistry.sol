// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "../ERC165Checker.sol";
import "../node/NodeInterface.sol";
import "./Anchor.sol";
import "../Owners.sol";

contract AnchorRegistry is Anchor, Owners {
    struct IssuanceRecord {
        address resolver; // root contract in the certification tree that issued the credential
        uint256 insertedBlock;
        uint256 blockTimestamp;
    }

    struct RevocationRecord {
        address resolver; 
        uint256 revokedBlock;
        bytes32 reason;
    }

    mapping(bytes32 => IssuanceRecord) private issued;
    mapping(bytes32 => RevocationRecord) private revoked;

    constructor(address[] memory registrars, uint8 quorum)
        Owners(registrars, quorum) {
            // solhint-disable-previous-line no-empty-blocks
    }

    function issue(bytes32 rootDigest, address issuerAddress) public override onlyOwner {
        require(!recordExists(rootDigest), "record already issued");
        require(!recordRevoked(rootDigest), "record revoked");
        require(issuerAddress != address(0x0),"sender cannot be 0");
        bool isNodeLike = ERC165Checker.supportsInterface(
            issuerAddress,
            type(NodeInterface).interfaceId
        );
        require(isNodeLike, "issuer is not a notary node");
        issued[rootDigest] = IssuanceRecord(
            issuerAddress,
            block.number,
            block.timestamp // solhint-disable-line not-rely-on-time
        );
        emit RecordIssued(rootDigest, msg.sender, block.number);
    }

    function revoke(bytes32 rootDigest, bytes32 reason) public override onlyOwner {
        require(recordExists(rootDigest), "record not found");
        IssuanceRecord storage record = issued[rootDigest];
        revoked[rootDigest] = RevocationRecord(
            record.resolver,
            block.number,
            reason
        );
        emit RecordRevoked(rootDigest, reason, msg.sender, block.number);
    }

    function resolver(bytes32 root) public view override returns (address) {
        return issued[root].resolver;
    }

    function recordExists(bytes32 root) public view override returns (bool) {
        return issued[root].insertedBlock != 0;
    }

    function recordRevoked(bytes32 root) public view override returns (bool) {
        return revoked[root].revokedBlock != 0;
    }
}
