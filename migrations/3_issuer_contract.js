var CredentialSum = artifacts.require("CredentialSum");
var Issuer = artifacts.require("IssuerMock");

module.exports = async function (deployer, network, accounts) {
    const [issuer1, issuer2] = accounts;

    deployer.link(CredentialSum, Issuer);
    return await deployer.deploy(Issuer, [issuer1, issuer2], 2);
};