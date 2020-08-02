const { time, BN, expectEvent, expectRevert } = require('@openzeppelin/test-helpers');
const { expect } = require('chai');
const { createNotary, createLeaves, generateLeafCredentials, aggregateSubTree, hash, hashByteArray } = require('./helpers/test-helpers');

const Issuer = artifacts.require('IssuerImpl');
const AccountableIssuer = artifacts.require('AccountableIssuerImpl');

contract('AccountableIssuer', accounts => {
    const [issuer1, issuer2, issuer3, subject, verifier, other] = accounts;
    let acIssuer, issuer, issuerAddress = null;
    const digest = hash(web3.utils.toHex('root-certificates'));

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

        it('should not add a contract that isn\'t implements IssuerInterface', async () => {
            await expectRevert(
                acIssuer.addIssuer("0xE11BA2b4D45Eaed5996Cd0823791E0C93114882d", { from: issuer1 }),
                'invalid opcode'
            );
        });

        it('should not allow to add itself', async () => {
            await expectRevert(
                acIssuer.addIssuer(acIssuer.address, { from: issuer1 }),
                'AccountableIssuer: cannot add itself'
            );
        });

        it('should successfully add a contract that implements IssuerInterface', async () => {
            let acIssuer2 = await AccountableIssuer.new([issuer1], 1);
            await acIssuer.addIssuer(acIssuer2.address, { from: issuer1 });
            (await acIssuer.isIssuer(acIssuer2.address)).should.equal(true);

            await acIssuer.addIssuer(issuer.address, { from: issuer1 });
            (await acIssuer.isIssuer(issuer.address)).should.equal(true);
        });

        it('should revert if given issuer address isn\'t a valid address', async () => {
            await expectRevert(
                acIssuer.addIssuer("0x0000NOT0A0ADDRESS000000", { from: issuer1 }),
                'invalid address'
            );
        });
    });

    describe('issuing root credential', () => {
        let wAddresses = [];

        beforeEach(async () => {
            acIssuer = await AccountableIssuer.new([issuer1, issuer2], 2);
            let issuerObj = await createNotary("leaf", issuer1, [issuer3]);
            await acIssuer.addIssuer(issuerObj.address, { from: issuer1 });

            let witnesses = await generateLeafCredentials([issuerObj], [subject], 4);
            wAddresses = witnesses.map(w => w.address);
        });

        it('should issue a root credential', async () => {
            [evidencesRoot, aggregationPerWitness] = await aggregateSubTree(acIssuer, subject);
            await acIssuer.registerCredential(subject, digest, wAddresses, { from: issuer1 });

            let c = await acIssuer.issuedCredentials(digest);
            (c.evidencesRoot).should.equal(evidencesRoot);
            expect(await acIssuer.getWitnesses(digest)).to.have.same.members(wAddresses);
        });

        it('should confirm a root credential', async () => {
            [evidencesRoot, aggregationPerWitness] = await aggregateSubTree(acIssuer, subject);
            await acIssuer.registerCredential(subject, digest, wAddresses, { from: issuer1 });

            (await acIssuer.certified(digest)).should.equal(false);

            // FIXME: As reported in the bug: https://github.com/trufflesuite/truffle/issues/2868
            // The following is the workaround for the hidden overloaded method:
            await acIssuer.methods["registerCredential(address,bytes32)"](subject, digest, { from: issuer2 });

            await acIssuer.confirmCredential(digest, { from: subject });

            (await acIssuer.certified(digest)).should.equal(true);
        });

        it('should revert if some of the leaves isn\'t aggregated', async () => {
            await expectRevert(
                acIssuer.registerCredential(subject, digest, wAddresses, { from: issuer1 }),
                "AccountableIssuer: aggregation on sub-contract not found"
            );
        });

        it('should revert if there is no sufficient number of sub-issuers', async () => {
            await expectRevert(
                acIssuer.registerCredential(subject, digest, []),
                'AccountableIssuer: require at least one issuer'
            );
        });

        it('should revert for unauthorized issuer', async () => {
            let unauthorized = await Issuer.new([issuer1], 1);
            await expectRevert(
                acIssuer.registerCredential(subject, digest, [unauthorized.address], { from: issuer1 }),
                "AccountableIssuer: issuer's address doesn't found"
            );
        });
    });

    describe('aggregating root credential', () => {
        let wAddresses = [];

        beforeEach(async () => {
            acIssuer = await AccountableIssuer.new([issuer1], 1);
            let issuerObj = await createNotary("leaf", issuer1, [issuer2]);
            await acIssuer.addIssuer(issuerObj.address, { from: issuer1 });

            let witnesses = await generateLeafCredentials([issuerObj], [subject], 4);
            wAddresses = witnesses.map(w => w.address);

            [evidencesRoot, aggregationPerWitness] = await aggregateSubTree(acIssuer, subject);

            await acIssuer.registerCredential(subject, digest, wAddresses, { from: issuer1 });

            await acIssuer.confirmCredential(digest, { from: subject });
        });

        it('should aggregate credentials on root contract', async () => {
            await acIssuer.aggregateCredentials(subject, { from: issuer1 });
            let rootProof = await acIssuer.getProof(subject);
            (rootProof).should.equal(hashByteArray([digest]));
        });
    });

    describe('verifying root credential', () => {
        let wAddresses = [];
        let rootProof = null;
        const ZERO_BYTES32 = '0x0000000000000000000000000000000000000000000000000000000000000000';

        beforeEach(async () => {
            acIssuer = await AccountableIssuer.new([issuer1], 1);

            let leaves = await createLeaves(acIssuer, issuer1, [[issuer2], [issuer3]]);

            // Generate credentials on leaves
            let witnesses = await generateLeafCredentials(leaves, [subject], 4);
            wAddresses = witnesses.map(w => w.address);

            // Aggregate on leaves
            await aggregateSubTree(acIssuer, subject);

            // generate root credential
            await acIssuer.registerCredential(subject, digest, wAddresses, { from: issuer1 });
            await acIssuer.confirmCredential(digest, { from: subject });
        });

        it('should successfully verify a valid set of credentials', async () => {
            // Aggregate on root
            await acIssuer.aggregateCredentials(subject, { from: issuer1 });
            rootProof = await acIssuer.getProof(subject);

            (await acIssuer.verifyCredentialTree(subject, rootProof)).should.equal(true);
        });

        it('should revert if given root is zero', async () => {
            await expectRevert(
                acIssuer.verifyCredentialTree(subject, ZERO_BYTES32),
                'AccountableIssuer: root proof should not be zero'
            );
        });

        it('should revert if root proof doesn\'t match', async () => {
            await expectRevert(
                acIssuer.verifyCredentialTree(subject, hash("something")),
                "Issuer: proof doesn't match or not exists"
            );
        });
    });

    describe('revoke', () => {
        const reason = hash(web3.utils.toHex('revoked'));
        let wAddresses = [];
        let rootProof = null;
        const ZERO_BYTES32 = '0x0000000000000000000000000000000000000000000000000000000000000000';

        beforeEach(async () => {
            acIssuer = await AccountableIssuer.new([issuer1], 1);

            let leaves = await createLeaves(acIssuer, issuer1, [[issuer2], [issuer3]]);

            // Generate credentials on leaves
            let witnesses = await generateLeafCredentials(leaves, [subject], 4);
            wAddresses = witnesses.map(w => w.address);

            // Aggregate on leaves
            await aggregateSubTree(acIssuer, subject);

            // generate root credential
            await acIssuer.registerCredential(subject, digest, wAddresses, { from: issuer1 });
            await acIssuer.confirmCredential(digest, { from: subject });
        });

        it('should successfully create a root revocation proof', async () => {
            await acIssuer.revokeCredential(digest, reason, { from: issuer1 });

            const revocation = await acIssuer.revokedCredentials(digest);
            expect(await time.latestBlock()).to.be.bignumber.equal(new BN(revocation.revokedBlock));
            assert.equal(revocation.reason, reason);
            assert.equal(revocation.subject, subject);
            assert.equal(revocation.issuer, issuer1);
        });
    });
});