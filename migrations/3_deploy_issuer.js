// Libs
const NotaryLib = artifacts.require('Notary');
const CredentialSumLib = artifacts.require('CredentialSum');

// Contracts
const Issuer = artifacts.require('IssuerMock');

module.exports = async function (deployer, network, accounts) {
    const [registrar1, registrar2] = accounts;

    console.log(`--- Deploying issuer at ${network} network ---`);
    await deployer.link(NotaryLib, Issuer);
    await deployer.link(CredentialSumLib, Issuer);
    await deployer.deploy(Issuer, [registrar1, registrar2], 2);
};
