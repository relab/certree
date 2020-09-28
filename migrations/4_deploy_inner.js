// Libs
var NotaryLib = artifacts.require("Notary");
var CredentialSumLib = artifacts.require("CredentialSum");
var Ctree = artifacts.require("Ctree");

// Contracts
var Inner = artifacts.require("InnerMock");

module.exports = async function (deployer, network, accounts) {
    const [issuer1, issuer2] = accounts;

    console.log(`--- Deploying inner at ${network} network ---`);
    await deployer.link(Ctree, Inner);
    await deployer.link(CredentialSumLib, Inner);
    await deployer.link(NotaryLib, Inner);
    await deployer.deploy(Inner, [issuer1, issuer2], 2);
};