// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

interface Anchor {
    // Logged when a record is issued/created.
    event RecordIssued(
        bytes32 indexed digest,
        address indexed registrar,
        uint256 insertedBlock
    );

    // Logged when a Record is revoked.
    event RecordRevoked(
        bytes32 indexed digest,
        bytes32 indexed reason,
        address indexed revoker,
        uint256 revokedBlock
    );

    function issue(bytes32, address) external;
    function revoke(bytes32, bytes32) external;
    function resolver(bytes32) external view returns (address);
    function recordExists(bytes32) external view returns (bool);
    function recordRevoked(bytes32) external view returns (bool);
}