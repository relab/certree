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
        bool approved; // Whether the subject approved the credential
        uint256 insertedBlock; // The block number of the proof creation
        uint256 blockTimestamp; // The block timestamp of the proof creation
        uint256 nonce; // Increment-only counter of credentials of the same subject
        address issuer; // The issuer address of this proof
        address subject; // The entity address refered by a proof
        bytes32 digest; // The digest of the credential stored (e.g. Swarm/IPFS hash)
        bytes32 evidencesRoot; // if is a leaf root is zero otherwise is the result of the aggregation of the digests at the witnesses
        address[] witnesses; // if witnesses is empty is a leaf notary, otherwise is a list of inner notaries
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
     * @return true if an emission proof exists, false otherwise.
     */
    function isIssued(CredentialTree storage self, bytes32 digest) public view returns (bool) {
        return self.issued[digest].digest != bytes32(0);
    }

    /**
     * @notice verify if a credential proof was revoked
     * @return true if a revocation exists, false otherwise.
     */
    function isRevoked(CredentialTree storage self, bytes32 digest) public view returns (bool) {
        return self.revoked[digest].revokedBlock != 0;
    }

    /**
     * @notice Verify if a digest was already certified
     * (i.e. signed by all parties)
     */
    function certified(CredentialTree storage self, bytes32 digest) public view returns (bool) {
        return self.issued[digest].approved;
    }

    /**
     * @notice issue a credential proof ensuring an append-only property
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
                Notary.CredentialProof memory c = self.issued[previousDigest];
                // Ensure that a previous certificate happens before the new one.
                // solhint-disable-next-line expression-indent
                require(c.insertedBlock < block.number, "Notary/block number violation");
                // solhint-disable-next-line not-rely-on-time, expression-indent
                require(c.blockTimestamp < block.timestamp, "Notary/timestamp violation");
            }
            self.issued[digest] = CredentialProof(
                1,
                false,
                block.number,
                block.timestamp, // solhint-disable-line not-rely-on-time
                self.nonce[subject],
                msg.sender,
                subject,
                digest,
                eRoot,
                witnesses
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
    }

    /**
     * @notice approve the emission of a quorum signed credential proof
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
        // emit CredentialSigned(msg.sender, digest, block.number);
        return true;
    }

    /**
     * @notice register the revocation of a credential
     * @dev can be called either by the issuer or by the subject
     * of the credential
     */
    // TODO: quorum approval for revocation?
    function _revoke(CredentialTree storage self, bytes32 digest, bytes32 reason) internal {
        require(
            self.issued[digest].insertedBlock != 0,
            "Notary/credential not found"
        );
        address subject = self.issued[digest].subject;
        assert(subject != address(0));
        self.revoked[digest] = Notary.RevocationProof(
            msg.sender, // who is this sender?
            subject,
            block.number,
            reason
        );
        // TODO: analyse the consequence of deleting the proof.
        // delete self.issued[digest];
        // emit CredentialRevoked(
        //     digest,
        //     subject,
        //     msg.sender,
        //     block.number,
        //     reason
        // );
    }
}