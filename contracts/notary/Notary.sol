// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;
pragma experimental ABIEncoderV2;

library Notary {
    /**
     * @notice CredentialProof represents an on-chain proof that a
     * verifiable credential was created and signed by a registrar.
     * @dev it is a node of the credential tree of a subject.
     */
    struct CredentialProof {
        uint256 signed; // Amount of owners who signed
        uint256 insertedBlock; // The block number of the proof creation
        uint256 blockTimestamp; // The block timestamp of the proof creation
        uint256 nonce; // Increment-only counter of credentials of the same subject
        bytes32 digest; // The digest of the credential stored (e.g. Swarm/IPFS hash)
        bool approved; // Whether the subject approved the credential
        address registrar; // The registrar address
        address subject; // The entity address refered by a proof
        address[] witnesses; // if witnesses is empty is a leaf notary, otherwise is a list of inner notaries
        bytes32 evidenceRoot; // if is a leaf root is zero otherwise is the result of the aggregation of the digests at the witnesses
    }

    /**
     * @notice RevocationProof represents an on-chain proof that a
     * verifiable credential was revoked by a registrar.
     */
    struct RevocationProof {
        address registrar;
        address subject;
        uint256 revokedBlock; // The block number of the revocation (0 if not revoked)
        bytes32 reason; // digest of the reason of the revocation
    }

    /**
     * @notice define the credential tree structure
     */
    struct CredentialTree {
        // Incremental-only counter for registered credentials per subject
        mapping(address => uint256) nonce;
        // Maps the last issued digests by subjects
        // May be not valid yet
        mapping(address => bytes32) previous;
        // Maps issued credential proofs by subjects
        // The size of issued[subject] is the number of
        // issued credentials, and can contain revoked.
        mapping(address => bytes32[]) issued;
        // Maps registered credentials proof by the document digest
        mapping(bytes32 => CredentialProof) records;
        // Maps document digest to revoked proof
        mapping(bytes32 => RevocationProof) revoked;
        // Count the number of revoked credentials per subject
        mapping(address => uint256) revokedCounter;
        // Maps digest to owners that already signed it
        mapping(bytes32 => mapping(address => bool)) credentialSigners;
    }

    // Logged when a credential is issued/created.
    event CredentialIssued(
        bytes32 indexed digest,
        address indexed subject,
        address indexed registrar,
        uint256 insertedBlock
    );

    // Logged when a credential is revoked by some owner or by the subject.
    event CredentialRevoked(
        bytes32 indexed digest,
        address indexed subject,
        address indexed revoker,
        uint256 revokedBlock,
        bytes32 reason
    );

    // Logged when a credential is signed.
    event CredentialSigned(
        address indexed signer,
        bytes32 indexed digest,
        uint256 signedBlock
    );

    /**
     * @param digest The digest of the credential
     * @return the issued credential proof
     */
    function getCredentialProof(CredentialTree storage self, bytes32 digest)
        public
        view
        returns (CredentialProof memory)
    {
        return self.records[digest];
    }

    /**
     * @param digest The digest of the credential
     * @return the revoked credential proof
     */
    function getRevokedProof(CredentialTree storage self, bytes32 digest)
        public
        view
        returns (RevocationProof memory)
    {
        return self.revoked[digest];
    }

    /**
     * @notice verify if a credential proof exists for a given digest
     * @param digest The digest of the credential
     * @return true if an emission proof exists, false otherwise.
     */
    function recordExists(CredentialTree storage self, bytes32 digest)
        public
        view
        returns (bool)
    {
        return self.records[digest].digest != bytes32(0);
    }

    /**
     * @notice verify if a credential proof was revoked
     * @param digest The digest of the credential
     * @return true if a revocation exists, false otherwise.
     */
    function isRevoked(CredentialTree storage self, bytes32 digest)
        public
        view
        returns (bool)
    {
        return self.revoked[digest].revokedBlock != 0;
    }

    /**
     * @notice verify if a credential proof was signed by a quorum
     * @param digest The digest of the credential
     * @param quorumSize The size of the quorum
     */
    function isQuorumSigned(
        CredentialTree storage self,
        bytes32 digest,
        uint8 quorumSize
    ) public view returns (bool) {
        return self.records[digest].signed >= quorumSize;
    }

    /**
     * @notice returns whether a credential proof was signed
     * by a registrar's account
     * @param digest The digest of the credential
     * @param account The registrar's account
     */
    function isSigned(
        CredentialTree storage self,
        bytes32 digest,
        address account
    ) public view returns (bool) {
        return self.credentialSigners[digest][account];
    }

    /**
     * @notice verify if a credential was signed by all parties
     * @param digest The digest of the credential to be verified
     */
    function isApproved(CredentialTree storage self, bytes32 digest)
        public
        view
        returns (bool)
    {
        return self.records[digest].approved;
    }

    /**
     * @notice issue a credential proof ensuring an append-only property
     * @param subject The subject of the credential
     * @param digest The digest of the credential
     * @param eRoot The resulted hash of all witnesses' roots
     * @param witnesses The list of all witnesses contracts
     */
    function _issue(
        CredentialTree storage self,
        address subject,
        bytes32 digest,
        bytes32 eRoot,
        address[] memory witnesses
    ) internal {
        require(
            !self.credentialSigners[digest][msg.sender],
            "Notary/sender already signed"
        );
        if (self.records[digest].insertedBlock == 0) {
            // Creation
            if (self.previous[subject] != bytes32(0)) {
                assert(self.records[self.previous[subject]].insertedBlock != 0);
                CredentialProof memory c = self.records[self.previous[subject]];
                // Ensure that a previous certificate happens before the new one.
                require(
                    c.insertedBlock < block.number,
                    "Notary/block number violation"
                );
                require(
                    // solhint-disable-next-line not-rely-on-time
                    c.blockTimestamp < block.timestamp,
                    "Notary/timestamp violation"
                );
            }
            self.records[digest] = CredentialProof(
                1,
                block.number,
                block.timestamp, // solhint-disable-line not-rely-on-time
                ++self.nonce[subject],
                digest,
                false,
                msg.sender,
                subject,
                witnesses,
                eRoot
            );
            self.previous[subject] = digest;
            emit CredentialIssued(digest, subject, msg.sender, block.number);
        } else {
            require(
                self.records[digest].subject == subject,
                "Notary/already registered"
            );
            // Register sign action
            ++self.records[digest].signed;
        }
        self.credentialSigners[digest][msg.sender] = true;
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    /**
     * @notice approve the emission of a quorum signed credential proof
     * @param digest The digest of the credential
     * @dev must be called by the subject of the credential
     */
    function _approve(
        CredentialTree storage self,
        bytes32 digest,
        uint256 quorum
    ) internal returns (bool) {
        address subject = self.records[digest].subject;
        require(subject == msg.sender, "Notary/wrong subject");
        require(
            !self.records[digest].approved,
            "Notary/credential already signed"
        );
        require(
            self.records[digest].signed >= quorum,
            "Notary/no quorum of signatures"
        );
        // Mark the record as approved
        self.records[digest].approved = true;
        // Add the record to the issued list
        self.issued[subject].push(digest);
        // FIXME: emit events here or in the contract?
        emit CredentialSigned(msg.sender, digest, block.number);
        return true;
    }

    /**
     * @notice revokeCredential revokes a credential for a given reason
     * based on it's digest.
     * @param digest The digest of the credential
     * @param reason The hash of the reason of the revocation
     * @dev The reason should be publicaly available for anyone to inspect
     * (i.e. Stored in a public swarm/ipfs address). The function can be
     * called either by the registrar or by the subject of the credential.
     */
    //TODO: should we ensure that the sender is one of the owners here?
    // or only on the caller?
    // To check it here, the lib will need to keep the contract owners too
    function _revoke(
        CredentialTree storage self,
        bytes32 digest,
        bytes32 reason
    ) internal {
        require(
            self.records[digest].insertedBlock != 0,
            "Notary/credential not found"
        );
        address subject = self.records[digest].subject;
        require(subject != address(0), "Notary/subject cannot be zero");
        ++self.revokedCounter[subject];
        self.revoked[digest] = RevocationProof(
            msg.sender,
            subject,
            block.number,
            reason
        );
        // TODO: analyse the consequence of deleting the proof.
        // delete self.records[digest];
        // FIXME: If revoked credentials are kept in the `issued`
        // array and the verification checks whether the credential
        // was revoked, when verifying all credentails to aggregate,
        // if there is at least one credential revoked,
        // the verification will always fail, and consequently the aggregation.
        // As the digests order is important for the aggregation,
        // the array cannot be efficiently updated by moving the
        // last element into deleted indexes.
        // An alternative approach for ignore revoked digests
        // in the verification and aggregation may be necessary.
        emit CredentialRevoked(
            digest,
            subject,
            msg.sender,
            block.number,
            reason
        );
    }

    /**
     * @notice verifyCredential checks whether the credential is valid.
     * @dev A valid credential is the one signed by all parties and that
     * is not revoked.
     * @param subject The subject of the credential
     * @param digest The digest of the credential
     */
    function _verifyCredential(
        CredentialTree storage self,
        address subject,
        bytes32 digest
    ) internal view returns (bool) {
        require(
            self.records[digest].insertedBlock != 0,
            "Notary/credential not found"
        );
        require(
            self.records[digest].subject == subject,
            "Notary/not owned by subject"
        );
        return isApproved(self, digest) && !isRevoked(self, digest);
    }

    /**
     * @notice _verifyProofs checks whether a list of given proofs are valid
     * @param subject The subject of the credential
     * @param digests The list of digests of the proofs
     */
    function _verifyProofs(
        CredentialTree storage self,
        address subject,
        bytes32[] memory digests
    ) internal view returns (bool) {
        // FIXME: restrict size of `digests` array
        for (uint256 i = 0; i < digests.length; i++) {
            if (!_verifyCredential(self, subject, digests[i])) {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice _verifyIssuedCredentials checks whether all issued credentials
     * of a given subject are valid.
     * @param subject The subject of the credential
     */
    // TODO: Add period verification
    function _verifyIssuedCredentials(
        CredentialTree storage self,
        address subject
    ) internal view returns (bool) {
        // TODO: filter revoked? Return a list of revoked digests?
        return _verifyProofs(self, subject, self.issued[subject]);
    }
}
