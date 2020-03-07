var CredentialSum = artifacts.require("CredentialSum");

module.exports = async function (deployer) {
    return await deployer.deploy(CredentialSum);
};