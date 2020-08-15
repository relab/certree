// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

library Notary {
    // Logged when a credential is issued/created.
    event CredentialIssued(
        bytes32 indexed digest,
        address indexed subject,
        address indexed issuer,
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
     * @notice CredentialProof represents an on-chain proof that a
     * verifiable credential was created and signed by an issuer.
     * @dev it is a node of the credential tree of a subject.
     */
    struct CredentialProof {
        uint256 signed; // Amount of owners who signed
        uint256 insertedBlock; // The block number of the proof creation
        uint256 blockTimestamp; // The block timestamp of the proof creation
        uint256 nonce; // Increment-only counter of credentials of the same subject
        bytes32 digest; // The digest of the credential stored (e.g. Swarm/IPFS hash)
        bool approved; // Whether the subject approved the credential
        address issuer; // The issuer address of this proof
        address subject; // The entity address refered by a proof
        address[] witnesses; // if witnesses is empty is a leaf notary, otherwise is a list of inner notaries
        bytes32 evidencesRoot; // if is a leaf root is zero otherwise is the result of the aggregation of the digests at the witnesses
    }

    /**
     * @notice RevocationProof represents an on-chain proof that a
     * verifiable credential was revoked by an issuer.
     */
    struct RevocationProof {
        address issuer;
        address subject;
        uint256 revokedBlock; // The block number of the revocation (0 if not revoked)
        bytes32 reason; // digest of the reason of the revocation
    }

    /**
     * @notice define the credential tree structure
     */
    struct CredentialTree {
        // Incremental-only counter for issued credentials per subject
        mapping(address => uint256) nonce;

        // Maps credential digests by subjects
        mapping(address => bytes32[]) digests;

        // Maps issued credential proof by document digest
        mapping(bytes32 => CredentialProof) issued;

        // Maps document digest to revoked proof
        mapping(bytes32 => RevocationProof) revoked;

        // Maps digest to owners that already signed it
        mapping(bytes32 => mapping(address => bool)) ownersSigned;
    }

    /**
     * @notice verify if a credential proof was issued
     * @param digest The digest of the credential
     * @return true if an emission proof exists, false otherwise.
     */
    function _isIssued(CredentialTree storage self, bytes32 digest) internal view returns (bool) {
        return self.issued[digest].digest != bytes32(0);
    }

    /**
     * @notice verify if a credential proof was revoked
     * @param digest The digest of the credential
     * @return true if a revocation exists, false otherwise.
     */
    function _isRevoked(CredentialTree storage self, bytes32 digest) internal view returns (bool) {
        return self.revoked[digest].revokedBlock != 0;
    }

    /**
     * @notice verify if a credential was signed by all parties
     * @param digest The digest of the credential to be verified
     */
    function _certified(CredentialTree storage self, bytes32 digest) internal view returns (bool) {
        return self.issued[digest].approved;
    }

    /**
     * @notice issue a credential proof ensuring an append-only property
     * @param subject The subject of the credential
     * @param digest The digest of the credential
     * @param eRoot The resulted hash of all witnesses' roots
     * @param witnesses The list of all witnesses contracts
     */
    function _issue(CredentialTree storage self, address subject, bytes32 digest, bytes32 eRoot, address[] memory witnesses)
        internal
    {
        require(
            !self.ownersSigned[digest][msg.sender],
            "Notary/sender already signed"
        );
        if (self.issued[digest].insertedBlock == 0) {
            // Creation
            uint256 lastNonce;
            if (self.nonce[subject] == 0) {
                lastNonce = self.nonce[subject];
            } else {
                assert(self.nonce[subject] > 0);
                lastNonce = self.nonce[subject] - 1;
                assert(self.digests[subject].length > 0);
                bytes32 previousDigest = self.digests[subject][lastNonce];
                CredentialProof memory c = self.issued[previousDigest];
                // Ensure that a previous certificate happens before the new one.
                // solhint-disable-next-line expression-indent
                require(c.insertedBlock < block.number, "Notary/block number violation");
                // solhint-disable-next-line not-rely-on-time, expression-indent
                require(c.blockTimestamp < block.timestamp, "Notary/timestamp violation");
            }
            self.issued[digest] = CredentialProof(
                1,
                block.number,
                block.timestamp, // solhint-disable-line not-rely-on-time
                self.nonce[subject],
                digest,
                false,
                msg.sender,
                subject,
                witnesses,
                eRoot
            );
            ++self.nonce[subject];
            self.digests[subject].push(digest); // append subject's credential hash
            emit CredentialIssued(digest, subject, msg.sender, block.number);
        } else {
            require(
                self.issued[digest].subject == subject,
                "Notary/credential already issued"
            );
            // Register sign action
            ++self.issued[digest].signed;
        }
        self.ownersSigned[digest][msg.sender] = true;
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    /**
     * @notice approve the emission of a quorum signed credential proof
     * @param digest The digest of the credential
     * @dev must be called by the subject of the credential
     */
    function _approve(CredentialTree storage self, bytes32 digest, uint quorum) internal returns (bool) {
        require(
            self.issued[digest].subject == msg.sender,
            "Notary/wrong subject"
        );
        require(
            !self.issued[digest].approved,
            "Notary/credential already signed"
        );
        require(
            self.issued[digest].signed >= quorum,
            "Notary/no quorum of signatures"
        );
        self.issued[digest].approved = true;
        // EMIT events here or in the implementer?
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
     * called either by the issuer or by the subject of the credential.
     */
    function _revoke(CredentialTree storage self, bytes32 digest, bytes32 reason) internal {
        require(
            self.issued[digest].insertedBlock != 0,
            "Notary/credential not found"
        );
        address subject = self.issued[digest].subject;
        assert(subject != address(0));
        self.revoked[digest] = RevocationProof(
            msg.sender, // who is this sender?
            subject,
            block.number,
            reason
        );
        // TODO: analyse the consequence of deleting the proof.
        // delete self.issued[digest];
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
    function _verifyCredential(CredentialTree storage self, address subject, bytes32 digest)
        internal
        view
        returns (bool)
    {
        require(
            self.issued[digest].insertedBlock != 0,
            "Issuer/credential not found"
        );
        require(
            self.issued[digest].subject == subject,
            "Issuer/not owned by subject"
        );
        return (_certified(self, digest) && _isRevoked(self, digest));
    }

    /**
     * @notice verifyAllCredentials checks whether all credentials
     * of a given subject are valid.
     * @param subject The subject of the credential
     */
    // TODO: Add period verification
    function _verifyAllCredentials(CredentialTree storage self, address subject)
        internal
        view
        returns (bool)
    {
        // FIXME: restrict size of `digests` array
        for (uint256 i = 0; i < self.digests[subject].length; i++) {
            if (!_verifyCredential(self, subject, self.digests[subject][i])) {
                return false;
            }
        }
        return true;
    }
}