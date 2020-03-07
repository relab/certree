pragma solidity >=0.5.13 <0.7.0;
pragma experimental ABIEncoderV2;

import "../AccountableIssuer.sol";
import "./IssuerMock.sol";

contract AccountableIssuerMock is AccountableIssuer {
    mapping(address => IssuerMock) public issuersMap;

    event IssuerCreated(address indexed issuerAddress);
    event AggregationCreated(bytes32[] certificates);

    constructor(address[] memory owners, uint256 quorum)
        public
        AccountableIssuer(owners, quorum)
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    function createIssuer(address[] memory owners, uint256 quorum) public {
        IssuerMock issuer = new IssuerMock(owners, quorum);
        issuersMap[address(issuer)] = issuer;
        isIssuer[address(issuer)] = true;
        issuers.push(address(issuer));
        emit IssuerCreated(address(issuer));
    }

    function generateAggregation(address subject) public {
        bytes32[] memory aggregations = new bytes32[](issuers.length);
        for (uint256 i = 0; i < issuers.length; i++) {
            aggregations[i] = issuersMap[issuers[i]].aggregateCredentials(
                subject
            );
        }
        emit AggregationCreated(aggregations);
    }

    function setBalance() public payable {
        // address(this).balance += msg.value;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
