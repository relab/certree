const { time, BN, expectEvent, expectRevert } = require('@openzeppelin/test-helpers');
const { expect } = require('chai');
const { createNotary, createLeaves, generateLeafCredentials, aggregateSubTree, hash, hashByteArray } = require('./helpers/test-helpers');
const constants = require('@openzeppelin/test-helpers/src/constants');

const Inner = artifacts.require('InnerMock');

// Node roles
const LEAF_ROLE = 0;
const INNER_ROLE = 1;

contract.only('Inner', accounts => {
    const [registrar1, registrar2, registrar3, subject, verifier, other, deployer] = accounts;
    let inner, leaf, issuerAddress = null;
    const digest = hash(web3.utils.toHex('root-certificates'));

    describe('constructor', () => {
        it('should successfully deploy the contract with correct default values', async () => {
            inner = await Inner.new([registrar1, registrar2], 2, { from: deployer });
            expect(await inner.getRole()).to.be.bignumber.equal(new BN(INNER_ROLE));
            (await inner.myParent()).should.equal(deployer);
            (await inner.isLeaf()).should.equal(false);
            (await inner.initialized()).should.equal(false);
            (await inner.issuer()).should.equal(constants.ZERO_ADDRESS);
            (await inner.isOwner(registrar1)).should.equal(true);
            (await inner.isOwner(registrar2)).should.equal(true);
            expect(await inner.quorum()).to.be.bignumber.equal(new BN(2));
        });
    });

    describe('issuer initialization', () => {
        beforeEach(async () => {
            inner = await Inner.new([registrar1], 1, { from: deployer });
        });

        it('should successfully initialize an issuer instance', async () => {
            await inner.initializeIssuer({ from: registrar1 });

            (await inner.issuer()).should.not.equal(constants.ZERO_ADDRESS);
            (await inner.initialized()).should.equal(true);
        });

        it('should only allow owners to initialize an issuer instance', async () => {
            await expectRevert(
                inner.initializeIssuer({ from: other }),
                "Owners/sender is not an owner"
            );
            (await inner.issuer()).should.equal(constants.ZERO_ADDRESS);
            (await inner.initialized()).should.equal(false);
        });

        it('should only allow invocation of issuer\'s contract methods when it is already initialized', async () => {
            await expectRevert(
                inner.registerCredential(subject, digest, [], { from: registrar1 }),
                "Node/notarization not initialized"
            );
        });

        it('should only call initialize once', async () => {
            await inner.initializeIssuer({ from: registrar1 });
            (await inner.initialized()).should.equal(true);

            await expectRevert(
                inner.initializeIssuer({ from: registrar1 }),
                "Node/notarization already initialized"
            );
        });
    });

    describe('add node', () => {
        beforeEach(async () => {
            inner = await Inner.new([registrar1, registrar2], 2);
            leaf = await Leaf.deployed([registrar1], 1, { from: registrar1 });
            issuerAddress = leaf.address;
        });

        it('should not add an leaf from a unauthorized address', async () => {
            await expectRevert(
                inner.addIssuer(issuerAddress, { from: other }),
                'Owners: sender is not an owner'
            );
        });

        it('should not add an leaf from a unauthorized address', async () => {
            await expectRevert(
                inner.addChild(issuerAddress, { from: other }),
                'Owners: sender is not an owner'
            );
        });

        it('should add an leaf', async () => {
            const { logs } = await inner.addIssuer(issuerAddress, { from: registrar1 });

            expectEvent.inLogs(logs, 'IssuerAdded', {
                addedBy: registrar1,
                issuerAddress: issuerAddress
            });
        });

        it('should not add the same leaf twice', async () => {
            await inner.addChild(issuerAddress, { from: registrar1 });

            await expectRevert(
                inner.addIssuer(issuerAddress, { from: registrar2 }),
                'Inner: leaf already added'
            );
        });

        it('should not add a contract that isn\'t implements IssuerInterface', async () => {
            await expectRevert(
                inner.addIssuer("0xE11BA2b4D45Eaed5996Cd0823791E0C93114882d", { from: registrar1 }),
                'invalid opcode'
            );
        });

        it('should not allow to add itself', async () => {
            await expectRevert(
                inner.addIssuer(inner.address, { from: registrar1 }),
                'Inner: cannot add itself'
            );
        });

        it('should successfully add a contract that implements IssuerInterface', async () => {
            let acIssuer2 = await Inner.new([registrar1], 1);
            await inner.addIssuer(acIssuer2.address, { from: registrar1 });
            (await inner.authorizedIssuer(acIssuer2.address)).should.equal(true);

            await inner.addIssuer(leaf.address, { from: registrar1 });
            (await inner.authorizedIssuer(leaf.address)).should.equal(true);
        });

        it('should revert if given leaf address isn\'t a valid address', async () => {
            await expectRevert(
                inner.addIssuer("0x0000NOT0A0ADDRESS000000", { from: registrar1 }),
                'invalid address'
            );
        });
    });

    describe('issuing root credential', () => {
        let wAddresses = [];

        beforeEach(async () => {
            inner = await Inner.new([registrar1, registrar2], 2);
            let issuerObj = await createNotary("leaf", registrar1, [registrar3]);
            await inner.addIssuer(issuerObj.address, { from: registrar1 });

            let witnesses = await generateLeafCredentials([issuerObj], [subject], 4);
            wAddresses = witnesses.map(w => w.address);
        });

        it('should issue a root credential', async () => {
            [evidencesRoot, aggregationPerWitness] = await aggregateSubTree(inner, subject);
            await inner.registerCredential(subject, digest, wAddresses, { from: registrar1 });

            let c = await inner.issuedCredentials(digest);
            (c.evidencesRoot).should.equal(evidencesRoot);
            expect(await inner.getWitnesses(digest)).to.have.same.members(wAddresses);
        });

        it('should confirm a root credential', async () => {
            [evidencesRoot, aggregationPerWitness] = await aggregateSubTree(inner, subject);
            await inner.registerCredential(subject, digest, wAddresses, { from: registrar1 });

            (await inner.isApproved(digest)).should.equal(false);

            // FIXME: As reported in the bug: https://github.com/trufflesuite/truffle/issues/2868
            // The following is the workaround for the hidden overloaded method:
            await inner.methods["registerCredential(address,bytes32)"](subject, digest, { from: registrar2 });

            await inner.confirmCredential(digest, { from: subject });

            (await inner.isApproved(digest)).should.equal(true);
        });

        it('should revert if some of the leaves isn\'t aggregated', async () => {
            await expectRevert(
                inner.registerCredential(subject, digest, wAddresses, { from: registrar1 }),
                "Inner: aggregation on sub-contract not found"
            );
        });

        it('should revert if there is no sufficient number of sub-issuers', async () => {
            await expectRevert(
                inner.registerCredential(subject, digest, []),
                'Inner: require at least one leaf'
            );
        });

        it('should revert for unauthorized leaf', async () => {
            let unauthorized = await Leaf.new([registrar1], 1);
            await expectRevert(
                inner.registerCredential(subject, digest, [unauthorized.address], { from: registrar1 }),
                "Inner: leaf's address doesn't found"
            );
        });
    });

    describe('aggregating root credential', () => {
        let wAddresses = [];

        beforeEach(async () => {
            inner = await Inner.new([registrar1], 1);
            let issuerObj = await createNotary("leaf", registrar1, [registrar2]);
            await inner.addIssuer(issuerObj.address, { from: registrar1 });

            let witnesses = await generateLeafCredentials([issuerObj], [subject], 4);
            wAddresses = witnesses.map(w => w.address);

            [evidencesRoot, aggregationPerWitness] = await aggregateSubTree(inner, subject);

            await inner.registerCredential(subject, digest, wAddresses, { from: registrar1 });

            await inner.confirmCredential(digest, { from: subject });
        });

        it('should aggregate credentials on root contract', async () => {
            await inner.aggregateCredentials(subject, { from: registrar1 });
            let rootProof = await inner.getProof(subject);
            (rootProof).should.equal(hashByteArray([digest]));
        });
    });

    describe('verifying root credential', () => {
        let wAddresses = [];
        let rootProof = null;
        const ZERO_BYTES32 = '0x0000000000000000000000000000000000000000000000000000000000000000';

        beforeEach(async () => {
            inner = await Inner.new([registrar1], 1);

            let leaves = await createLeaves(inner, registrar1, [[registrar2], [registrar3]]);

            // Generate credentials on leaves
            let witnesses = await generateLeafCredentials(leaves, [subject], 4);
            wAddresses = witnesses.map(w => w.address);

            // Aggregate on leaves
            await aggregateSubTree(inner, subject);

            // generate root credential
            await inner.registerCredential(subject, digest, wAddresses, { from: registrar1 });
            await inner.confirmCredential(digest, { from: subject });
        });

        it('should successfully verify a valid set of credentials', async () => {
            // Aggregate on root
            await inner.aggregateCredentials(subject, { from: registrar1 });
            rootProof = await inner.getProof(subject);

            (await inner.verifyCredentialTree(subject, rootProof)).should.equal(true);
        });

        it('should revert if given root is zero', async () => {
            await expectRevert(
                inner.verifyCredentialTree(subject, ZERO_BYTES32),
                'Inner: root proof should not be zero'
            );
        });

        it('should revert if root proof doesn\'t match', async () => {
            await expectRevert(
                inner.verifyCredentialTree(subject, hash("something")),
                "Leaf: proof doesn't match or not exists"
            );
        });
    });

    describe('revoke', () => {
        const reason = hash(web3.utils.toHex('revoked'));
        let wAddresses = [];
        let rootProof = null;
        const ZERO_BYTES32 = '0x0000000000000000000000000000000000000000000000000000000000000000';

        beforeEach(async () => {
            inner = await Inner.new([registrar1], 1);

            let leaves = await createLeaves(inner, registrar1, [[registrar2], [registrar3]]);

            // Generate credentials on leaves
            let witnesses = await generateLeafCredentials(leaves, [subject], 4);
            wAddresses = witnesses.map(w => w.address);

            // Aggregate on leaves
            await aggregateSubTree(inner, subject);

            // generate root credential
            await inner.registerCredential(subject, digest, wAddresses, { from: registrar1 });
            await inner.confirmCredential(digest, { from: subject });
        });

        it('should successfully create a root revocation proof', async () => {
            await inner.revokeCredential(digest, reason, { from: registrar1 });

            const revocation = await inner.revokedCredentials(digest);
            expect(await time.latestBlock()).to.be.bignumber.equal(new BN(revocation.revokedBlock));
            assert.equal(revocation.reason, reason);
            assert.equal(revocation.subject, subject);
            assert.equal(revocation.leaf, registrar1);
        });
    });
});