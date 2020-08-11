// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

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
        address indexed aggregator,
        address indexed subject,
        bytes32 indexed proof,
        uint256 aggregatedBlock
    );

    modifier existsRoot(Root storage self) {
        require(self.proof != bytes32(0), "CredentialSum: proof not exists");
        //TODO: if is != zero, then use it as input too in the aggregation
        _;
    }

    function getRoot(Root storage self)
        public
        pure
        returns (Root storage)
    {
        return self;
    }

    function hasRoot(Root storage self)
        public
        view
        returns (bool)
    {
        return self.proof != bytes32(0);
    }

    // Aggregate credentials and produce a proof of it
    function generateRoot(Root storage self, address subject, bytes32[] memory digests)
        public
        returns (bytes32)
    {
        require(
            digests.length > 0,
            "CredentialSum: the list of digests must not be empty"
        );
        //TODO: if (self.proof != bytes32(0)) append to it
        bytes32 root = computeRoot(digests);
        self.proof = root;
        self.insertedBlock = block.number;
        // solhint-disable-next-line not-rely-on-time, expression-indent
        self.blockTimestamp = block.timestamp;
        // TODO: sender should be issuer not contract
        emit AggregatedRoot(msg.sender, subject, root, block.number);
        return root;
    }

    function computeRoot(bytes32[] memory digests)
        public
        pure
        returns (bytes32)
    {
        require(
            digests.length > 0,
            "CredentialSum: the list of digests must not be empty"
        );
        // FIXME: consider use sha256(abi.encode(digests));
        return keccak256(abi.encode(digests));
    }

    /**
     * @dev verifySelfRoot checks if the stored proof was generated using
     * the given list of digests
     */
    function verifySelfRoot(Root storage self, bytes32[] memory digests)
        public
        view
        existsRoot(self)
        returns (bool)
    {
        return (self.proof == computeRoot(digests));
    }

    /**
     * @dev verifyRoot checks if the given list of digests generates the
     * requested proof
     */
    function verifyRoot(bytes32 root, bytes32[] calldata digests)
        external
        pure
        returns (bool)
    {
        return (root == computeRoot(digests));
    }
}
