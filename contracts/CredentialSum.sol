// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.7.0;

library CredentialSum {

    // TODO: Define a better name instead of just proof
    // Root or Aggregation?
    // Proof represents the result of the aggregation of all
    // subject's credential digests on the contract state
    struct Proof {
        mapping(address => bytes32) _proofs;
    }

    // Logged when a credential is aggregated.
    event AggregatedProof(
        address indexed aggregator,
        address indexed subject,
        bytes32 indexed proof,
        uint256 aggregatedBlock
    );

    // Aggregate credentials and produce a proof of it
    function generateProof(Proof storage self, address subject, bytes32[] memory certificates)
        public
        returns (bytes32)
    {
        require(
            certificates.length > 0,
            "CredentialSum: there is no certificates"
        );
        // if (self._proofs[subject] != bytes32(0)) append to it
        bytes32 proof = makeRoot(certificates);
        self._proofs[subject] = proof;
        // TODO: sender should be issuer not contract
        emit AggregatedProof(msg.sender, subject, proof, block.number);
        return proof;
    }

    function makeRoot(bytes32[] memory digests)
        public
        pure
        returns (bytes32)
    {
        require(
            digests.length > 0,
            "CredentialSum: there is no digests"
        );
        // FIXME: consider use sha256(abi.encode(digests));
        return keccak256(abi.encode(digests));
    }

    /**
     * @dev verifySelfProof checks if the stored proof was generated using
     * the given list of digests
     */
    function verifySelfProof(Proof storage self, address subject, bytes32[] memory digests)
        public
        view
        returns (bool)
    {
        require(self._proofs[subject] != bytes32(0), "CredentialSum: proof not exists"); // if is != zero, then use it as input too in the aggregation
        return (self._proofs[subject] == makeRoot(digests));
    }

    /**
     * @dev verifyProof checks if the given list of digests generates the
     * requested proof
     */
    function verifyProof(bytes32 proof, bytes32[] calldata digests)
        external
        pure
        returns (bool)
    {
        return (proof == makeRoot(digests));
    }

    function proofs(Proof storage self, address subject)
        public
        view
        returns (bytes32)
    {
        return self._proofs[subject];
    }
}
