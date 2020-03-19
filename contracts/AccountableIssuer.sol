pragma solidity >=0.5.13 <0.7.0;
// pragma experimental ABIEncoderV2;

import "./Issuer.sol";
// import "@openzeppelin/contracts/math/SafeMath.sol";
// import "@openzeppelin/contracts/cryptography/ECDSA.sol";

/**
 * @title AccountableIssuer's contract
 * This contract act as a factory contract for issuers and
 * consider implicit signatures verification already necessary
 * to perform valid transactions.
 * TODO Implement using EIP712:
 * https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md
 */
abstract contract AccountableIssuer is Issuer {
    address[] public issuers;

    // Map of all issuers sub-contracts
    mapping(address => bool) public isIssuer;

    // Logged when an issuer added.
    event IssuerAdded(
        address indexed issuerAddress,
        address indexed addedBy
    );

    //TODO: blacklist issuers?

    constructor(address[] memory owners, uint256 quorum)
        public
        Issuer(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    /**
     * @return the length of the issuers array
     */
    function issuersLength() public view returns (uint256) {
        return issuers.length;
    }

    function addIssuer(address issuerAddress) onlyOwner public {
        require(!isIssuer[issuerAddress], "AccountableIssuer: issuer already added");
        // TODO: check if is an issuer contract before add it?
        Issuer issuer = Issuer(issuerAddress);
        assert(address(issuer) == issuerAddress);
        isIssuer[issuerAddress] =  true;
        issuers.push(issuerAddress);
        emit IssuerAdded(issuerAddress, msg.sender);
    }

    /**
     * @dev collectCredentials collect all the aggregated digests of 
     * a given subject in all sub-contracts levels.
     */
    function collectCredentials(address subject, address[] memory issuersAddresses)
        public
        view
        onlyOwner
        returns (bytes32[] memory)
    {
        require(issuersAddresses.length > 0, "AccountableIssuer: require at least one issuer");
        bytes32[] memory digests = new bytes32[](issuersAddresses.length);
        for (uint256 i = 0; i < issuersAddresses.length; i++) {
            address issuerAddress = address(issuersAddresses[i]);
            require(isIssuer[issuerAddress], "AccountableIssuer: issuer's address doesn't found");
            Issuer issuer = Issuer(issuerAddress);
            bytes32 proof = issuer.getProof(subject);
            require(proof != bytes32(0), "AccountableIssuer: aggregation on sub-contract not found");
            digests[i] = proof;
        }
        return digests;
    }

    function registerCredential(
        address subject,
        bytes32 digest,
        bytes32 digestRoot,
        address[] memory issuersAddresses
    ) public onlyOwner {
        require(aggregatedProofs.proofs(subject) == bytes32(0), "AccountableIssuer: credentials already aggregated, not possible to issue new credentials");
        bytes32[] memory d = collectCredentials(subject, issuersAddresses);
        bytes32[] memory digests = new bytes32[](d.length + 1);
        uint256 i = 0;
        for (; i < d.length; i++) {
            digests[i] = d[i];
        }
        // Add current credential
        digests[i] = digest;
        bytes32 aggregatedDigest =  aggregatedProofs.generateProof(subject, digests);
        require(aggregatedDigest == digestRoot, "AccountableIssuer: root is not equal");
        _issue(subject, digest);
        emit CredentialSigned(msg.sender, digest, block.number);
    }

    /**
     * @dev verifyCredential iteractivally verifies if a given credential
     * (i.e. represented by it's digest) corresponds to the aggregation 
     * of all stored credentials of a particular subject in all given contracts.
     * @param subject is the subject referred by all credentials to be verified.
     * @param proofs is an array containing the resulted aggregated hashes of
     * all issuers in "issuersAddresses" plus the final issued digest.
     * @param issuersAddresses is an array with the address of all authorized
     * issuers that stores the subject credentials.
     */
    function verifyCredential(address subject, bytes32[] memory proofs, address[] memory issuersAddresses) public view returns(bool) {
        require(issuersAddresses.length > 0, "AccountableIssuer: require at least one issuer");
        for (uint256 i = 0; i < issuersAddresses.length; i++) {
            address issuerAddress = address(issuersAddresses[i]);
            require(isIssuer[issuerAddress], "AccountableIssuer: address not registered");
            Issuer issuer = Issuer(issuerAddress);
            assert(issuer.verifyCredential(subject, proofs[i])); //verify leaves construction
        }
        return aggregatedProofs.verifyProof(subject, proofs); //verify root construction
    }
}
