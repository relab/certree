// Contracts
const Anchor = artifacts.require("AnchorRegistry");

module.exports = async function (deployer, network, accounts) {
    const [registrar1, registrar2] = accounts;
    console.log(`--- Deploying anchor at ${network} network ---`);
    await deployer.deploy(Anchor, [registrar1, registrar2], 2);
};
