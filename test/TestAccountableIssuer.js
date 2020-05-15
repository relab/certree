const { BN, expectEvent, expectRevert, time } = require('@openzeppelin/test-helpers');
const { expect } = require('chai');

const Issuer = artifacts.require('IssuerMock');
const AccountableIssuer = artifacts.require('AccountableIssuerMock');
const Owners = artifacts.require('Owners');

async function generateLeafCredentials(contract, numberOfIssuers, acIssuerOwner, issuerOwners, subject) {
    let issuerAddresses = [];
    var certsPerIssuer = [];

    for (i = 0; i < numberOfIssuers; i++) {
        let { logs } = await contract.createIssuer(issuerOwners, issuerOwners.length, { from: acIssuerOwner });
        let issuerContract = await Issuer.at(logs[0].args.issuerAddress);
        issuerAddresses.push(issuerContract.address);

        for (j = 0; j < i + numberOfIssuers; j++) {
            let certificateDigest = web3.utils.keccak256(web3.utils.toHex(`certificate${i}-${j}`));
            await issuerContract.createSignedLeafCredential(subject, certificateDigest, { from: issuerOwners[0] });
            await time.increase(time.duration.seconds(1));
        }
        certsPerIssuer.push(await issuerContract.digestsBySubject(subject));
    }
    return { issuerAddresses, certsPerIssuer };
}

async function aggregateCredentials(contract, acIssuerOwner, subject) {
    let { logs } = await contract.generateAggregation(subject, { from: acIssuerOwner });

    let aggregationsPerIssuer = (logs.find(e => e.event == "AggregationCreated")).args.certificates;
    return aggregationsPerIssuer
}

function hash(certs) {
    return web3.utils.keccak256(web3.eth.abi.encodeParameter('bytes32[]', certs));
}

contract('AccountableIssuer', accounts => {
    const [issuer1, issuer2, issuer3, subject, other] = accounts;
    let acIssuer, issuer, issuerAddress = null;
    const digest = web3.utils.keccak256(web3.utils.toHex('root-certificates'));


    describe('constructor', () => {
        it('should successfully deploy the contract', async () => {
            acIssuer = await AccountableIssuer.new([issuer1, issuer2], 2);
            (await acIssuer.isOwner(issuer1)).should.equal(true);
            (await acIssuer.isOwner(issuer2)).should.equal(true);
            expect(await acIssuer.quorum()).to.be.bignumber.equal(new BN(2));
        });
    });

    describe('add issuer', () => {
        beforeEach(async () => {
            acIssuer = await AccountableIssuer.new([issuer1, issuer2], 2);
            issuer = await Issuer.deployed([issuer1], 1, { from: issuer1 });
            issuerAddress = issuer.address;
        });

        it('should not add an issuer from a unauthorized address', async () => {
            await expectRevert(
                acIssuer.addIssuer(issuerAddress, { from: other }),
                'Owners: sender is not an owner'
            );
        });

        it('should add an issuer', async () => {
            const { logs } = await acIssuer.addIssuer(issuerAddress, { from: issuer1 });

            expectEvent.inLogs(logs, 'IssuerAdded', {
                addedBy: issuer1,
                issuerAddress: issuerAddress
            });
        });

        it('should not add the same issuer twice', async () => {
            await acIssuer.addIssuer(issuerAddress, { from: issuer1 });

            await expectRevert(
                acIssuer.addIssuer(issuerAddress, { from: issuer2 }),
                'AccountableIssuer: issuer already added'
            );
        });
    });

    describe('issuing root credential', () => {
        let issuerAddresses, aggregationsPerIssuer = [];
        let expectedRoot = null;

        beforeEach(async () => {
            acIssuer = await AccountableIssuer.new([issuer1, issuer2], 2);
            ({ issuerAddresses } = await generateLeafCredentials(acIssuer, 2, issuer1, [issuer3], subject));

            aggregationsPerIssuer = await aggregateCredentials(acIssuer, issuer1, subject);

            aggregationsPerIssuer.push(digest);
            expectedRoot = hash(aggregationsPerIssuer);
        });

        it('should issue a root credential', async () => {
            // FIXME: As reported in the bug: https://github.com/trufflesuite/truffle/issues/2868
            // The following is the workaround for the hidden overloaded method:
            await acIssuer.methods["registerCredential(address,bytes32,bytes32,address[])"](subject, digest, expectedRoot, issuerAddresses, { from: issuer1 });

            let rootCertificate = (await acIssuer.digestsBySubject(subject))[0];
            (rootCertificate).should.equal(digest);
        });

        it('should confirm a root credential', async () => {
            await acIssuer.methods["registerCredential(address,bytes32,bytes32,address[])"](subject, digest, expectedRoot, issuerAddresses, { from: issuer1 });

            let rootCertificate = (await acIssuer.digestsBySubject(subject))[0];
            (rootCertificate).should.equal(digest);

            (await acIssuer.certified(digest)).should.equal(false);

            await acIssuer.registerCredential(subject, digest, { from: issuer2 });
            await acIssuer.confirmCredential(digest, { from: subject });

            (await acIssuer.certified(digest)).should.equal(true);
        });

        it('should revert if the given root doesn\'t match', async () => {
            const wrongRoot = web3.utils.keccak256(web3.utils.toHex('wrongRoot'));
            await expectRevert(
                acIssuer.methods["registerCredential(address,bytes32,bytes32,address[])"](subject, digest, wrongRoot, issuerAddresses, { from: issuer1 }),
                'AccountableIssuer: given proof could not be generated with existing credentials'
            );
        });
    });

    describe('verifying credential', () => {
        let issuerAddresses, aggregationsPerIssuer = [];
        const ZERO_BYTES32 = '0x0000000000000000000000000000000000000000000000000000000000000000';

        beforeEach(async () => {
            acIssuer = await AccountableIssuer.new([issuer1], 1);
            ({ issuerAddresses } = await generateLeafCredentials(acIssuer, 2, issuer1, [issuer2], subject));

            aggregationsPerIssuer = await aggregateCredentials(acIssuer, issuer1, subject);
        });

        it('should successfully verify a valid set of credentials', async () => {
            (await acIssuer.verifyCredential(subject, aggregationsPerIssuer, issuerAddresses)).should.equal(true);
        });

        it('should revert if there is no sufficient number of issuers', async () => {
            await expectRevert(
                acIssuer.verifyCredential(subject, aggregationsPerIssuer, []),
                'AccountableIssuer: require at least one issuer'
            );
        });

        it('should revert if given issuer isn\'t a valid address', async () => {
            await expectRevert(
                acIssuer.verifyCredential(subject, aggregationsPerIssuer, ["0x0000NOT0A0ADDRESS000000"]),
                'invalid address'
            );
        });

        it('should revert if given issuer isn\'t authorized', async () => {
            let issuer = await Issuer.new([other], 1);
            await expectRevert(
                acIssuer.verifyCredential(subject, aggregationsPerIssuer, [issuer.address]),
                'AccountableIssuer: address not registered'
            );
        });

        it('should revert if given contract isn\'t an issuer instance', async () => {
            let something = await Owners.new([other], 1);
            await acIssuer.addIssuer(something.address); // force addition of wrong contract
            await expectRevert.unspecified(
                acIssuer.verifyCredential(subject, aggregationsPerIssuer, [something.address])
            );
        });

        it('should revert if the proof doesn\'t exists', async () => {
            i = aggregationsPerIssuer.length - 1;
            wrongDigests = aggregationsPerIssuer.slice(0, i)
            wrongDigests.push(ZERO_BYTES32);

            let issuer = await Issuer.at(issuerAddresses[i]);
            await issuer.deleteProof(subject);

            await expectRevert(
                acIssuer.verifyCredential(subject, wrongDigests, issuerAddresses),
                'CredentialSum: proof not exists'
            );
        });

        it('should revert if there is no proof on sub-contracts', async () => {
            let issuer = await Issuer.new([other], 1);
            await acIssuer.addIssuer(issuer.address);
            await expectRevert(
                acIssuer.verifyCredential(subject, aggregationsPerIssuer, [issuer.address]),
                'Issuer: proof doesn\'t match or not exists');
        });

        it('should revert if proofs don\'t match', async () => {
            let fakeCerts = []
            for (let i = 0; i < 3; i++) {
                fakeCerts[i] = web3.utils.keccak256(web3.utils.toHex(`someValue-${i}`));
            }

            await expectRevert(
                acIssuer.verifyCredential(subject, fakeCerts, issuerAddresses),
                'Issuer: proof doesn\'t match or not exists'
            );
        });
    });
});