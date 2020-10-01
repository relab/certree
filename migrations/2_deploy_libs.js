var NotaryLib = artifacts.require("Notary");
var CredentialSumLib = artifacts.require("CredentialSum");

module.exports = async function (deployer, network) {
    console.log(`--- Deploying Libs at ${network} network ---`);
    await deployer.deploy(NotaryLib);
    await deployer.deploy(CredentialSumLib);
};