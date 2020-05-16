// SPDX-License-Identifier: MIT
pragma solidity >=0.5.13 <0.7.0;
pragma experimental ABIEncoderV2;

import "./IssuerInterface.sol";
import "./Owners.sol";
import "./CredentialSum.sol";


// import "@openzeppelin/contracts/math/SafeMath.sol";

// TODO: how to manage key changes? e.g. a student that lost his previous key. Reissue the certificates may not work, since the time ordering, thus a possible solution is the contract to store a key update information for the subject, or something like that.

/**
 * @title Issuer's contract ensures that verifiable credentials are correctly
 * issued by untrusted issuers, discouraging fraudulent processes by
 * establishing a casual order between the certificates.
 */
 // TODO: Ensure interface implementation: https://eips.ethereum.org/EIPS/eip-165
 // TODO: Allow upgradeable contract using similar approach of https://github.com/PeterBorah/ether-router
abstract contract Issuer is IssuerInterface, Owners {
    // using SafeMath for uint256;
    bool private _isLeaf = true;

    // Result of an aggregation of all digests of one subject
    using CredentialSum for CredentialSum.Proof;
    CredentialSum.Proof aggregatedProof;

    /**
     * @dev CredentialProof represents an on-chain proof that a
     * verifiable credential was created and signed by an issuer.
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
        bytes32 evidencesRoot; // if is a leaf aggregatedProof is zero otherwise is the result of the aggregation of the digests at the witnesses
        address[] witnesses; // if witnesses is empty is a leaf notary, otherwise is a list of node notaries
    }

    /**
     * @dev RevocationProof represents an on-chain proof that a
     * verifiable credential was revoked by an issuer.
     */
    struct RevocationProof {
        address issuer;
        address subject;
        uint256 revokedBlock; // The block number of the revocation (0 if not revoked)
        bytes32 reason; // digest of the reason of the revocation
    }
    // TODO: add key revocation

    // Incremental-only counter for issued credentials per subject
    mapping(address => uint256) public nonce;

    // Maps credential digests by subjects
    mapping(address => bytes32[]) private _digestsBySubject;

    // Maps issued credential proof by document digest
    mapping(bytes32 => CredentialProof) public issuedCredentials;

    // Maps document digest to revoked proof
    mapping(bytes32 => RevocationProof) public revokedCredentials;

    // Maps digest to owners that already signed it
    mapping(bytes32 => mapping(address => bool)) public ownersSigned;

    /**
     * @dev Constructor creates an Issuer contract
     */
    constructor(address[] memory owners, uint256 quorum, bool isLeaf)
        public
        Owners(owners, quorum)
    {
        _isLeaf = isLeaf;
    }

    modifier notRevoked(bytes32 digest) {
        require(
            !isRevoked(digest),
            "Issuer: this credential was already revoked"
        );
        _;
    }

    /**
     * @return true if the issuer contract is a leaf
     */
    function isLeaf() public view returns(bool) {
        return _isLeaf;
    }

    /**
     * @return the registered digests of a subject
     */
    function digestsBySubject(address subject)
        public
        view
        returns (bytes32[] memory)
    {
        return _digestsBySubject[subject];
    }

    /**
     * @return the aggregated proof of a subject
     */
    function getProof(address subject) public view returns (bytes32) {
        return aggregatedProof.proofs(subject);
    }

    /**
     * @dev verify if a credential proof was revoked
     * @return true if a revocation exists, false otherwise.
     */
    function isRevoked(bytes32 digest) public view override returns (bool) {
        return revokedCredentials[digest].revokedBlock != 0;
    }

    function _issue(address subject, bytes32 digest, bytes32 eRoot,
        address[] memory witnesses)
        internal
        onlyOwner
        notRevoked(digest)
    {
        require(
            !ownersSigned[digest][msg.sender],
            "Issuer: sender already signed"
        );
        require(!isOwner[subject], "Issuer: subject cannot be the issuer");
        if (issuedCredentials[digest].insertedBlock == 0) {
            // Creation
            uint256 lastNonce;
            if (nonce[subject] == 0) {
                lastNonce = nonce[subject];
            } else {
                assert(nonce[subject] > 0);
                lastNonce = nonce[subject] - 1;
                assert(_digestsBySubject[subject].length > 0);
                bytes32 previousDigest = _digestsBySubject[subject][lastNonce];
                CredentialProof memory c = issuedCredentials[previousDigest];
                // Ensure that a previous certificate happens before the new one.
                // solhint-disable-next-line expression-indent
                require(c.insertedBlock < block.number, "Issuer: new credential shouldn't happen at same block of the previous for the same subject");
                // solhint-disable-next-line not-rely-on-time, expression-indent
                require(c.blockTimestamp < block.timestamp, "Issuer: new credential shouldn't happen at same timestamp of the previous for the same subject");
            }
            issuedCredentials[digest] = CredentialProof(
                1,
                false,
                block.number,
                block.timestamp, // solhint-disable-line not-rely-on-time
                nonce[subject],
                msg.sender,
                subject,
                digest,
                eRoot,
                witnesses
            );
            ++nonce[subject];
            _digestsBySubject[subject].push(digest); // append subject's credential hash
            emit CredentialIssued(digest, subject, msg.sender, block.number);
        } else {
            require(
                issuedCredentials[digest].subject == subject,
                "Issuer: credential already issued for other subject"
            );
            // Register sign action
            ++issuedCredentials[digest].signed;
        }
        ownersSigned[digest][msg.sender] = true;
    }

    /**
     * @dev issue a credential proof ensuring an append-only property
     */
    function registerCredential(address subject, bytes32 digest)
        public
        virtual
        override
        onlyOwner
    {
        // TODO: verify the cost of the following approaches
        // bytes32 zero;
        // address[] memory none;
        _issue(subject, digest, bytes32(0), new address[](0));
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    /**
     * @dev Verify if a digest was already certified (i.e. signed by all parties)
     */
    function certified(bytes32 digest) public view override returns (bool) {
        return issuedCredentials[digest].approved;
    }

    /**
     * @dev confirms the emission of a quorum signed credential proof
     */
    function confirmCredential(bytes32 digest) public override notRevoked(digest) {
        CredentialProof storage proof = issuedCredentials[digest];
        require(
            proof.subject == msg.sender,
            "Issuer: subject is not related with this credential"
        );
        require(
            !proof.approved,
            "Issuer: subject already signed this credential"
        );
        require(
            proof.signed >= quorum,
            "Issuer: not sufficient quorum of signatures"
        );
        proof.approved = true;
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    /**
     * @dev revoke a credential proof
     */
    function revokeCredential(bytes32 digest, bytes32 reason)
        public
        override
        onlyOwner
        notRevoked(digest)
    {
        require(
            issuedCredentials[digest].insertedBlock != 0,
            "Issuer: no credential proof found"
        );
        address subject = issuedCredentials[digest].subject;
        assert(_digestsBySubject[subject].length > 0);
        revokedCredentials[digest] = RevocationProof(
            msg.sender,
            subject,
            block.number,
            reason
        );
        delete issuedCredentials[digest];
        emit CredentialRevoked(
            digest,
            subject,
            msg.sender,
            block.number,
            reason
        );
    }

    /**
     * @dev verifies if a list of digests are certified
     */
    function checkCredentials(bytes32[] memory digests)
        public
        view
        returns (bool)
    {
        require(
            digests.length > 0,
            "Issuer: there is no credential for the given subject"
        );
        for (uint256 i = 0; i < digests.length; i++) {
            if (!certified(digests[i])) {
                return false;
            } //&& !isRevoked(digests[i]));
            // all subject's certificates must be signed by all parties and should be valid
        }
        return true;
    }

    /**
     * @dev aggregateCredentials aggregates the digests of a given subject on the credential level
     */
    function aggregateCredentials(address subject)
        public
        virtual
        override
        onlyOwner
        returns (bytes32)
    {
        // TODO: ignore the revoke credentials in the aggregation
        bytes32[] memory digests = _digestsBySubject[subject];
        require(
            checkCredentials(digests),
            "Issuer: there are unsigned credentials"
        );
        return aggregatedProof.generateProof(subject, digests);
    }

    /**
     * @dev verifyCredentialLeaf verifies if the credential of a given subject
     * was correctly generated based on the root contract
     */
    function verifyCredentialLeaf(address subject, bytes32 croot)
        public
        view
        returns (bool)
    {
        bytes32 proof = aggregatedProof.proofs(subject);
        require(proof == croot, "Issuer: proof doesn't match or not exists");
        return aggregatedProof.verifySelfProof(
            subject,
            _digestsBySubject[subject]
        );
    }
}
