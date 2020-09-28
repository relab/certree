var NotaryLib = artifacts.require("Notary");
var CredentialSumLib = artifacts.require("CredentialSum");
var Ctree = artifacts.require("Ctree");

module.exports = async function (deployer, network) {
    console.log(`--- Deploying Libs at ${network} network ---`);
    await deployer.deploy(NotaryLib);
    await deployer.deploy(CredentialSumLib);
    await deployer.link(CredentialSumLib, Ctree);
    await deployer.deploy(Ctree);
};