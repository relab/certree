const NotaryLib = artifacts.require("Notary");
const CredentialSumLib = artifacts.require("CredentialSum");

module.exports = async function (deployer, network) {
    console.log(`--- Deploying Libs at ${network} network ---`);
    await deployer.deploy(NotaryLib);
    await deployer.deploy(CredentialSumLib);
};
