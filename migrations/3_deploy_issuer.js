// Libs
var NotaryLib = artifacts.require("Notary");
var CredentialSumLib = artifacts.require("CredentialSum");

// Contracts
var Issuer = artifacts.require("IssuerMock");

module.exports = async function (deployer, network, accounts) {
    const [issuer1, issuer2] = accounts;

    console.log(`--- Deploying issuer at ${network} network ---`);
    await deployer.link(NotaryLib, Issuer);
    await deployer.link(CredentialSumLib, Issuer);
    await deployer.deploy(Issuer, [issuer1, issuer2], 2);
};