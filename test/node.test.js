const { time, BN, expectEvent, expectRevert, constants } = require('@openzeppelin/test-helpers');
const { expect, assert } = require('chai');
const { createNotary, createLeaves, generateLeafCredentials, aggregateSubTree, hash, hashByteArray } = require('./helpers/test-helpers');
const assertFailure = require('./helpers/assert-failure');

const Inner = artifacts.require('InnerMock');
const Leaf = artifacts.require('LeafMock');
const Issuer = artifacts.require('IssuerMock');

// Node roles
const LEAF_ROLE = new BN(0);
const INNER_ROLE = new BN(1);

contract('Node', accounts => {
    const [registrar1, registrar2, registrar3, subject, verifier, other, deployer] = accounts;
    let inner, leaf = null;
    const digest = hash(web3.utils.toHex('root-certificates'));

    describe('constructor', () => {
        it('should successfully deploy the contract with correct default values', async () => {
            inner = await Inner.new([registrar1, registrar2], 2, { from: deployer });
            expect(await inner.getRole()).to.be.bignumber.equal(INNER_ROLE);
            (await inner.myParent()).should.equal(deployer);
            (await inner.isLeaf()).should.equal(false);
            (await inner.isOwner(registrar1)).should.equal(true);
            (await inner.isOwner(registrar2)).should.equal(true);
            expect(await inner.quorum()).to.be.bignumber.equal(new BN(2));
        });
    });

    describe('add node', () => {
        beforeEach(async () => {
            inner = await Inner.new([registrar1, registrar2], 2);
            leaf = await Leaf.new([registrar2], 1, { from: registrar2 });
        });

        it('should add an leaf node', async () => {
            const { logs } = await inner.addChild(leaf.address, { from: registrar1 });

            expectEvent.inLogs(logs, 'NodeAdded', {
                createdBy: registrar1,
                nodeAddress: leaf.address,
                role: LEAF_ROLE
            });
        });

        it('should not add the same leaf twice', async () => {
            await inner.addChild(leaf.address, { from: registrar1 });

            await expectRevert(
                inner.addChild(leaf.address, { from: registrar2 }),
                'Node/node already added'
            );
        });

        it('should not allow unauthorized users to add child contracts', async () => {
            await expectRevert(
                inner.addChild(leaf.address, { from: other }),
                'Owners/sender is not an owner'
            );
        });

        it('should not allow leaves to add child contracts', async () => {
            await expectRevert(
                leaf.addChild(inner.address, { from: registrar2 }),
                'Node/node must be Inner'
            );
        });

        it('should not add an address that does not implements IssuerInterface', async () => {
            await assertFailure(
                inner.addChild("0xE11BA2b4D45Eaed5996Cd0823791E0C93114882d", { from: registrar1 })
            );
        });

        it('should not add an address that does not implements NodeInterface', async () => {
            issuer = await Issuer.new([registrar2], 1, { from: registrar2 });
            await assertFailure(
                inner.addChild(issuer.address, { from: registrar1 })
            );
        });

        it('should not allow to add itself', async () => {
            await expectRevert(
                inner.addChild(inner.address, { from: registrar1 }),
                'Node/cannot add itself'
            );
        });

        it('should revert if given address is not valid', async () => {
            await expectRevert(
                inner.addChild("0x0000NOT0A0ADDRESS000000", { from: registrar1 }),
                'invalid address'
            );
        });
    });

    describe('issuing root credential', () => {
        let witnesses = {};
        let wAddresses = [];

        beforeEach(async () => {
            inner = await Inner.new([registrar1, registrar2], 2);
            let l = await createNotary("leaf", registrar1, [registrar3]);
            await inner.addChild(l.address, { from: registrar1 });

            witnesses = await generateLeafCredentials([l], [subject], 4);
            wAddresses = Object.keys(witnesses);
        });

        it('should issue a root credential', async () => {
            [evidenceRoot, aggregationPerWitness] = await aggregateSubTree(witnesses, subject);
            await inner.registerCredential(subject, digest, wAddresses, { from: registrar1 });

            let c = await inner.getCredentialProof(digest);
            (c.evidenceRoot).should.equal(evidenceRoot);
            expect(await inner.getWitnesses(digest)).to.have.same.members(wAddresses);
        });

        it('should confirm a root credential', async () => {
            [evidenceRoot, aggregationPerWitness] = await aggregateSubTree(witnesses, subject);
            await inner.registerCredential(subject, digest, wAddresses, { from: registrar1 });

            (await inner.isApproved(digest)).should.equal(false);

            await inner.registerCredential(subject, digest, wAddresses, { from: registrar2 });

            await inner.confirmCredential(digest, { from: subject });

            (await inner.isApproved(digest)).should.equal(true);
        });

        it('should revert if some of the leaves isn\'t aggregated', async () => {
            await expectRevert(
                inner.registerCredential(subject, digest, wAddresses, { from: registrar1 }),
                "Node/root not found"
            );
        });

        it('should revert if there is no sufficient number of witnesses', async () => {
            await expectRevert(
                inner.registerCredential(subject, digest, []),
                'Node/witness not found'
            );
        });

        it('should revert for unauthorized leaf', async () => {
            let unauthorized = await Leaf.new([registrar1], 1);
            await expectRevert(
                inner.registerCredential(subject, digest, [unauthorized.address], { from: registrar1 }),
                "Node/address not authorized"
            );
        });
    });

    describe('aggregating root credential', () => {
        let witnesses = {};
        let wAddresses = [];

        before(async () => {
            inner = await Inner.new([registrar1], 1);
            let l = await createNotary("leaf", registrar1, [registrar2]);
            await inner.addChild(l.address, { from: registrar1 });
            witnesses = await generateLeafCredentials([l], [subject], 4);
            wAddresses = Object.keys(witnesses);

            [evidenceRoot, aggregationPerWitness] = await aggregateSubTree(witnesses, subject);

            await inner.registerCredential(subject, digest, wAddresses, { from: registrar1 });

            await inner.confirmCredential(digest, { from: subject });
        });

        it('should aggregate credentials on root contract', async () => {
            await inner.aggregateCredentials(subject, [digest], { from: registrar1 });
            let rootProof = await inner.getRootProof(subject);
            (rootProof).should.equal(hashByteArray([digest]));
        });
    });

    describe('verifying root credential', () => {
        let witnesses = {};
        let wAddresses = [];

        beforeEach(async () => {
            inner = await Inner.new([registrar1], 1);

            let leaves = await createLeaves(inner, registrar1, [[registrar2], [registrar3]]);

            // Generate credentials on leaves
            witnesses = await generateLeafCredentials(leaves, [subject], 4);

            // Aggregate on leaves
            [evidenceRoot, aggregationPerWitness] = await aggregateSubTree(witnesses, subject);

            // generate root credential
            wAddresses = Object.keys(witnesses);
            await inner.registerCredential(subject, digest, wAddresses, { from: registrar1 });
            await inner.confirmCredential(digest, { from: subject });
        });

        it('should successfully verify a valid set of credentials', async () => {
            (await inner.verifyCredentialTree(subject)).should.equal(true);
        });

        it('should successfully verify the root and the valid set of credentials', async () => {
            // Aggregate on root
            await inner.aggregateCredentials(subject, [digest], { from: registrar1 });
            let rootProof = await inner.getRootProof(subject);

            (await inner.verifyCredentialTree(subject)).should.equal(true);
        });

        //TODO: add corner cases tests
    });

    describe('revoke', () => {
        const reason = hash(web3.utils.toHex('revoked'));
        let witnesses = {};
        let wAddresses = [];

        beforeEach(async () => {
            inner = await Inner.new([registrar1], 1);

            let leaves = await createLeaves(inner, registrar1, [[registrar2], [registrar3]]);

            // Generate credentials on leaves
            witnesses = await generateLeafCredentials(leaves, [subject], 4);

            // Aggregate on leaves
            [evidenceRoot, aggregationPerWitness] = await aggregateSubTree(witnesses, subject);

            // generate root credential
            wAddresses = Object.keys(witnesses);
            await inner.registerCredential(subject, digest, wAddresses, { from: registrar1 });
            await inner.confirmCredential(digest, { from: subject });
        });

        it('should successfully create a root revocation proof', async () => {
            await inner.revokeCredential(digest, reason, { from: registrar1 });

            const revocation = await inner.getRevokedProof(digest);
            expect(await time.latestBlock()).to.be.bignumber.equal(new BN(revocation.revokedBlock));
            assert.equal(revocation.registrar, registrar1)
            assert.equal(revocation.reason, reason);
            assert.equal(revocation.subject, subject);
        });
    });
});