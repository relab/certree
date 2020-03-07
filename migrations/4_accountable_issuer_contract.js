var CredentialSum = artifacts.require("CredentialSum");
var AccountableIssuer = artifacts.require("AccountableIssuerMock");

module.exports = async function (deployer, network, accounts) {
    const [issuer1, issuer2] = accounts;

    deployer.link(CredentialSum, AccountableIssuer);
    return await deployer.deploy(AccountableIssuer, [issuer1, issuer2], 2);
};