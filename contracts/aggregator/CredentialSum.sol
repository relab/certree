// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

library CredentialSum {
    // Root represents the result of the aggregation of all
    // subject's credential digests on the contract state
    struct Root {
        bytes32 proof;
        uint256 insertedBlock;
        uint256 blockTimestamp;
    }

    // Logged when a credential is aggregated.
    event AggregatedRoot(
        bytes32 indexed proof,
        address indexed aggregator,
        address indexed subject,
        uint256 aggregatedBlock
    );

    modifier rootExists(Root storage self) {
        require(hasRoot(self), "CredentialSum/proof not exists");
        //TODO: if is != zero, then use it as input too in the aggregation
        _;
    }

    modifier notEmpty(bytes32[] memory digests) {
        require(digests.length > 0, "CredentialSum/empty list");
        _;
    }

    function getRoot(Root storage self) public pure returns (Root storage) {
        return self;
    }

    function hasRoot(Root storage self) public view returns (bool) {
        return self.proof != bytes32(0);
    }

    // Aggregate credentials and produce a proof of it
    function generateRoot(
        Root storage self,
        address subject,
        bytes32[] memory digests
    ) public notEmpty(digests) returns (bytes32) {
        //TODO: if (self.proof != bytes32(0)) append to it
        bytes32 root = computeRoot(digests);
        self.proof = root;
        self.insertedBlock = block.number;
        // solhint-disable-next-line not-rely-on-time, expression-indent
        self.blockTimestamp = block.timestamp;
        // TODO: sender should be issuer not contract
        emit AggregatedRoot(root, msg.sender, subject, block.number);
        return root;
    }

    function computeRoot(bytes32[] memory digests) public pure notEmpty(digests) returns (bytes32) {
        // FIXME: consider use sha256(abi.encode(digests));
        return keccak256(abi.encode(digests));
    }

    /**
     * @dev verifySelfRoot checks if the stored root was generated using
     * the given list of digests
     */
    function verifySelfRoot(Root storage self, bytes32[] memory digests) public view rootExists(self) returns (bool) {
        return (self.proof == computeRoot(digests));
    }

    /**
     * @dev verifyRoot checks if the given list of digests generates the
     * given root
     */
    function verifyRoot(bytes32 root, bytes32[] calldata digests) public pure returns (bool) {
        return (root == computeRoot(digests));
    }
}
