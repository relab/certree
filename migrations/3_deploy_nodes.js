// Libs
const NotaryLib = artifacts.require('Notary');
const CredentialSumLib = artifacts.require('CredentialSum');

// Contracts
const Leaf = artifacts.require('LeafMock');
const Inner = artifacts.require('InnerMock');

module.exports = async function (deployer, network, accounts) {
    const [registrar1, registrar2] = accounts;

    console.log(`--- Deploying leaf at ${network} network ---`);
    await deployer.link(CredentialSumLib, Leaf);
    await deployer.link(NotaryLib, Leaf);
    await deployer.deploy(Leaf, [registrar1, registrar2], 2);

    console.log(`--- Deploying inner at ${network} network ---`);
    await deployer.link(CredentialSumLib, Inner);
    await deployer.link(NotaryLib, Inner);
    await deployer.deploy(Inner, [registrar1, registrar2], 2);
};
