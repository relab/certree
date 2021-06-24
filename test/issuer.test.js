const { BN, expectEvent, expectRevert, time, constants } = require("@openzeppelin/test-helpers");
const { expect } = require("chai");
const { hash, hashByteArray } = require("./helpers/test-helpers");

const Issuer = artifacts.require("IssuerMock");

contract("Issuer", accounts => {
    const [registrar1, registrar2, registrar3, subject1, subject2] = accounts;
    let issuer = null;
    const reason = hash(web3.utils.toHex("revoked"));
    const digest1 = hash(web3.utils.toHex("cert1"));
    const digest2 = hash(web3.utils.toHex("cert2"));
    const digest3 = hash(web3.utils.toHex("cert3"));

    describe("creation", () => {
        it("should successfully deploy the contract initializing the registrars", async () => {
            issuer = await Issuer.new([registrar1, registrar2], 2);
            (await issuer.isOwner(registrar1)).should.equal(true);
            (await issuer.isOwner(registrar2)).should.equal(true);
            expect(await issuer.quorum()).to.be.bignumber.equal(new BN(2));
        });

        it("should successfully get a deployed contract", async () => {
            issuer = await Issuer.deployed([registrar1, registrar2], 2);
            (await issuer.isOwner(registrar1)).should.equal(true);
            (await issuer.isOwner(registrar2)).should.equal(true);
            expect(await issuer.quorum()).to.be.bignumber.equal(new BN(2));
        });
    });

    describe("getters", () => {
        let issuer1; let issuer2 = null;
        let timestamp; let block = 0;
        const expectedRoot = hashByteArray([digest1, digest2]);

        before(async () => {
            issuer1 = await Issuer.new([registrar1], 1);
            await issuer1.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });
            await issuer1.approveCredential(digest1, { from: subject1 });

            await time.increase(time.duration.seconds(1));

            await issuer1.registerCredential(subject1, digest2, constants.ZERO_BYTES32, [], { from: registrar1 });
            await issuer1.approveCredential(digest2, { from: subject1 });

            await issuer1.aggregateCredentials(subject1, [digest1, digest2], { from: registrar1 });
            timestamp = await time.latest();
            block = await time.latestBlock();

            issuer2 = await Issuer.new([registrar2], 1);
            await issuer2.registerCredential(subject1, digest3, expectedRoot, [issuer1.address], { from: registrar2 });
        });

        it("should successfully retrieve registered digests", async () => {
            const digests = await issuer1.getDigests(subject1);
            expect(digests).to.include.members([digest1, digest2]);
        });

        it("should successfully retrieve the witnesses of a credential", async () => {
            const w = await issuer2.witnessesLength(digest3);
            expect(w).to.be.bignumber.equal(new BN(1));

            const witnesses = await issuer2.getWitnesses(digest3);
            expect(witnesses).to.include.members([issuer1.address]);
            (witnesses.length).should.equal(1);
        });

        it("should successfully retrieve the evidence root of a credential", async () => {
            const rootHash = await issuer2.getEvidenceRoot(digest3);
            (rootHash).should.equal(expectedRoot);
        });

        it("should successfully retrieve the root proof", async () => {
            const root = await issuer1.getProof(subject1);
            (root.proof).should.equal(expectedRoot);
            expect(root.blockTimestamp).to.be.bignumber.equal(timestamp);
            expect(root.insertedBlock).to.be.bignumber.equal(block);
        });

        it("should successfully retrieve all revoked digests", async () => {
            await issuer1.revokeCredential(digest2, reason, { from: registrar1 });

            const rc = await issuer1.revokedCounter(subject1);
            expect(rc).to.be.bignumber.equal(new BN(1));

            const revoked = await issuer1.getRevoked(subject1);
            expect(revoked).to.include.members([digest2]);
            (revoked.length).should.equal(1);
        });
    });

    describe("issuing", () => {
        beforeEach(async () => {
            issuer = await Issuer.new([registrar1, registrar2], 2);
        });

        it("should successfully create a credential proof", async () => {
            await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });

            const credential = await issuer.getCredentialProof(digest1);

            expect(credential.signed).to.be.bignumber.equal(new BN(1));
            (await issuer.isSigned(digest1, registrar1)).should.equal(true);
            expect(await time.latestBlock()).to.be.bignumber.equal(new BN(credential.insertedBlock));
            expect(await time.latest()).to.be.bignumber.equal(new BN(credential.blockTimestamp));
            expect(credential.nonce).to.be.bignumber.equal(new BN(1));
            assert.equal(credential.digest, digest1);
            (credential.approved).should.equal(false);
            assert.equal(credential.registrar, registrar1);
            assert.equal(credential.subject, subject1);
            /* eslint-disable-next-line no-unused-expressions */
            expect(credential.witnesses).to.be.an("array").that.is.empty;
            (credential.evidenceRoot).should.equal(constants.ZERO_BYTES32);
        });

        it("should successfully check if a credential exists", async () => {
            (await issuer.recordExists(digest1)).should.equal(false);

            await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });

            (await issuer.recordExists(digest1)).should.equal(true);
        });

        describe("revert", () => {
            it("should not register an already issued credential", async () => {
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });

                await expectRevert(
                    issuer.registerCredential(subject2, digest1, constants.ZERO_BYTES32, [], { from: registrar2 }),
                    "Notary/digest already registered"
                );
            });

            it("should not register a credential twice", async () => {
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });

                await expectRevert(
                    issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 }),
                    "Notary/sender already signed"
                );
            });

            it("should not allow a registrar to register credentials to themselves", async () => {
                await expectRevert(
                    issuer.registerCredential(registrar1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 }),
                    "Issuer/forbidden registrar"
                );
                await expectRevert(
                    issuer.registerCredential(registrar2, digest1, constants.ZERO_BYTES32, [], { from: registrar1 }),
                    "Issuer/forbidden registrar"
                );
            });

            it("should not allow register a credential from an unauthorized account", async () => {
                await expectRevert(
                    issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar3 }),
                    "Owners/sender is not an owner"
                );
            });

            it("should not allow re-issue a credential for different subjects", async () => {
                issuer = await Issuer.new([registrar1, registrar2], 1);
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });

                await expectRevert(
                    issuer.registerCredential(subject2, digest1, constants.ZERO_BYTES32, [], { from: registrar2 }),
                    "Notary/digest already registered"
                );
            });

            it.skip("should not allow to register a new credential at same timestamp of the previous one", async () => {
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });

                // Fail when try to register a credential at same timestamp of the previous
                await expectRevert(
                    issuer.registerCredential(subject1, digest2, constants.ZERO_BYTES32, [], { from: registrar1 }),
                    "Notary/timestamp violation"
                );
            });
        });

        describe("events", () => {
            it("should emit an issued and a signed event when a credential proof is registered", async () => {
                const { logs } = await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });

                const block = await time.latestBlock();
                expectEvent.inLogs(logs, "CredentialIssued", {
                    digest: digest1,
                    subject: subject1,
                    registrar: registrar1,
                    insertedBlock: block
                });
                expectEvent.inLogs(logs, "CredentialSigned", {
                    signer: registrar1,
                    digest: digest1,
                    signedBlock: block
                });
            });

            it("should emit a signed event when a credential proof is signed by a registrar", async () => {
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });
                const { logs } = await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar2 });

                const block = await time.latestBlock();
                expectEvent.inLogs(logs, "CredentialSigned", {
                    signer: registrar2,
                    digest: digest1,
                    signedBlock: block
                });
            });
        });
    });

    describe("quorum check", () => {
        let owners = [];
        let quorum = owners.length;

        beforeEach(async () => {
            issuer = await Issuer.new([registrar1, registrar2, registrar3], 2);
            owners = await issuer.owners(); // 3
            quorum = await issuer.quorum(); // 2
        });

        describe("normal behaviour", () => {
            it("should compute a quorum of registrar signatures", async () => {
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar2 });

                assert.equal(quorum, 2);
                for (let i = 0; i < owners.length; i++) {
                    const signed = await issuer.isSigned(digest1, owners[i]);
                    if (signed) --quorum;
                }
                (quorum).should.equal(0);
            });

            it("should check whether a credential has a quorum approval", async () => {
                (await issuer.isQuorumSigned(digest1)).should.equal(false);
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });

                (await issuer.isQuorumSigned(digest1)).should.equal(false);
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar2 });

                (await issuer.isQuorumSigned(digest1)).should.equal(true);
            });

            it("should return an array of zero address if there is no registrars' signatures", async () => {
                const signers = await issuer.getCredentialSigners(digest1);
                (signers.length).should.equal(owners.length);
                for (let i = 0; i < signers.length; i++) {
                    (signers[i]).should.equal(constants.ZERO_ADDRESS);
                }
            });

            it("should return the number of registrars that already sign a credential", async () => {
                // Two registrars sign the digest1
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar2 });

                const signers = await issuer.getCredentialSigners(digest1);
                (signers.length).should.equal(owners.length);
                expect(signers).to.be.an("array").that.does.not.include(registrar3);
                expect(signers).to.include.ordered.members([registrar1, registrar2]);
                // The last registrar does not sign it yet
                (signers[signers.length - 1]).should.equal(constants.ZERO_ADDRESS);
            });
        });
    });

    describe("approval", () => {
        describe("normal behaviour", () => {
            beforeEach(async () => {
                // Require 2 signatures/approval out of 3 owners
                issuer = await Issuer.new([registrar1, registrar2, registrar3], 2);
                // The creator of the credential sign it
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });
            });

            it("should revert when attempting to confirm a credential proof without a quorum of signatures", async () => {
                const credential = await issuer.getCredentialProof(digest1);
                (credential.approved).should.equal(false);

                await expectRevert(
                    issuer.approveCredential(digest1, { from: subject1 }),
                    "Notary/no quorum of signatures"
                );
            });

            it("should only allow confirmations from the correct subject", async () => {
                // The second issuer also sign
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar2 });

                await expectRevert(
                    issuer.approveCredential(digest1, { from: subject2 }),
                    "Notary/wrong subject"
                );
            });

            it("should not allow a subject to confirm twice the same credential proof", async () => {
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar2 });
                await issuer.approveCredential(digest1, { from: subject1 });

                await expectRevert(
                    issuer.approveCredential(digest1, { from: subject1 }),
                    "Notary/credential already signed"
                );
            });

            it("should mark a credential as approved when it was signed by a quorum of registrars and by the subject", async () => {
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar2 });
                await issuer.approveCredential(digest1, { from: subject1 });

                const credential = await issuer.getCredentialProof(digest1);
                (credential.approved).should.equal(true);
            });

            it("should check whether a credential was signed by all required parties (i.e. quorum + subject", async () => {
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar2 });

                (await issuer.isApproved(digest1)).should.equal(false);

                await issuer.approveCredential(digest1, { from: subject1 });

                (await issuer.isApproved(digest1)).should.equal(true);
            });
        });

        describe("events", () => {
            beforeEach(async () => {
                issuer = await Issuer.new([registrar1, registrar2, registrar3], 2);
            });

            it("should emit an event when a credential proof is signed by all required parties", async () => {
                const previousBlockNumber = await time.latestBlock();

                let { logs } = await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });
                let lastBlockNumber = await time.latestBlock();
                expectEvent.inLogs(logs, "CredentialIssued", {
                    digest: digest1,
                    subject: subject1,
                    registrar: registrar1,
                    insertedBlock: lastBlockNumber
                });
                expectEvent.inLogs(logs, "CredentialSigned", {
                    signer: registrar1,
                    digest: digest1,
                    signedBlock: lastBlockNumber
                });

                ({ logs } = await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar2 }));
                lastBlockNumber = await time.latestBlock();
                expectEvent.inLogs(logs, "CredentialSigned", {
                    signer: registrar2,
                    digest: digest1,
                    signedBlock: lastBlockNumber
                });

                ({ logs } = await issuer.approveCredential(digest1, { from: subject1 }));
                lastBlockNumber = await time.latestBlock();
                expectEvent.inLogs(logs, "CredentialSigned", {
                    signer: subject1,
                    digest: digest1,
                    signedBlock: lastBlockNumber
                });

                const eventList = await issuer.getPastEvents("allEvents", { fromBlock: previousBlockNumber, toBlock: lastBlockNumber });
                (eventList.length).should.equal(4);
            });
        });
    });

    describe("revocation", () => {
        beforeEach(async () => {
            issuer = await Issuer.new([registrar1, registrar2], 2);
            await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });
        });

        describe("normal behaviour", () => {
            it("should allow a registrar to successfully create a revocation proof", async () => {
                await issuer.revokeCredential(digest1, reason, { from: registrar1 });

                const revocation = await issuer.getRevokedProof(digest1);
                assert.equal(revocation.subject, subject1);
                assert.equal(revocation.registrar, registrar1);
                expect(await time.latestBlock()).to.be.bignumber.equal(new BN(revocation.revokedBlock));
                assert.equal(revocation.reason, reason);
            });

            it("should allow the subject to successfully create a revocation proof for his credential", async () => {
                await issuer.revokeCredential(digest1, reason, { from: subject1 });

                const revocation = await issuer.getRevokedProof(digest1);
                assert.equal(revocation.subject, subject1);
                assert.equal(revocation.registrar, subject1);
                expect(await time.latestBlock()).to.be.bignumber.equal(new BN(revocation.revokedBlock));
                assert.equal(revocation.reason, reason);
            });

            it("should verify whether a credential proof was revoked based on its digest", async () => {
                (await issuer.isRevoked(digest1)).should.equal(false);

                await issuer.revokeCredential(digest1, reason, { from: registrar1 });
                (await issuer.isRevoked(digest1)).should.equal(true);
            });
        });

        describe("revert", () => {
            it("should not revoke a credential proof from an un-authorized account", async () => {
                await expectRevert(
                    issuer.revokeCredential(digest1, reason, { from: registrar3 }),
                    "Issuer/sender not authorized"
                );
            });

            it("should not revoke a not issued credential proof", async () => {
                await expectRevert(
                    issuer.revokeCredential(digest2, reason, { from: registrar1 }),
                    "Notary/credential not found"
                );
            });

            it("should not approve a revoked credential", async () => {
                await issuer.revokeCredential(digest1, reason, { from: registrar1 });
                (await issuer.isRevoked(digest1)).should.equal(true);

                await expectRevert(
                    issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar2 }),
                    "Issuer/credential revoked"
                );
                (await issuer.isSigned(digest1, registrar1)).should.equal(true);
                (await issuer.isSigned(digest1, registrar2)).should.equal(false);
            });

            it("should not confirm a revoked credential", async () => {
                await issuer.revokeCredential(digest1, reason, { from: registrar2 });
                (await issuer.isRevoked(digest1)).should.equal(true);

                await expectRevert(
                    issuer.approveCredential(digest1, { from: subject1 }),
                    "Issuer/credential revoked"
                );
                (await issuer.isApproved(digest1)).should.equal(false);
            });

            it("should not revoke credential twice", async () => {
                await issuer.revokeCredential(digest1, reason, { from: registrar1 });
                (await issuer.isRevoked(digest1)).should.equal(true);

                await expectRevert(
                    issuer.revokeCredential(digest1, reason, { from: registrar2 }),
                    "Issuer/credential revoked"
                );
            });
        });

        describe("events", () => {
            it("should emits an event when create a revocation proof", async () => {
                const { logs } = await issuer.revokeCredential(digest1, reason, { from: registrar2 });
                const blockNumber = await time.latestBlock();

                expectEvent.inLogs(logs, "CredentialRevoked", {
                    digest: digest1,
                    subject: subject1,
                    revoker: registrar2,
                    revokedBlock: blockNumber,
                    reason: reason
                });

                (await issuer.isApproved(digest1)).should.equal(false);
            });
        });

        // TODO: analyse the consequence of deleting the proof
        it.skip("should delete the revoked credential", async () => {
            await issuer.revokeCredential(digest1, reason, { from: registrar2 });

            const credential = await issuer.getCredentialProof(digest1);
            assert.equal(credential.subject, constants.ZERO_ADDRESS);
            assert.equal(credential.registrar, constants.ZERO_ADDRESS);
            expect(credential.insertedBlock).to.be.bignumber.equal(new BN(0));

            (await issuer.isApproved(digest1)).should.equal(false);
        });
    });

    describe("verify credentials", () => {
        const digests = [digest1, digest2];

        beforeEach(async () => {
            issuer = await Issuer.new([registrar1], 1);
            for (const d of digests) {
                await issuer.registerCredential(subject1, d, constants.ZERO_BYTES32, [], { from: registrar1 });
                await issuer.approveCredential(d, { from: subject1 });
                await time.increase(time.duration.seconds(1));

                (await issuer.isApproved(d)).should.equal(true);
            }
        });

        describe("normal behaviour", () => {
            it("should check the root proof", async () => {
                await issuer.aggregateCredentials(subject1, digests);
                (await issuer.verifyRootOf(subject1, digests)).should.equal(true);
            });

            it("should check whether a credential was signed by all required parties", async () => {
                (await issuer.verifyCredential(subject1, digest1)).should.equal(true);
            });

            it("should check whether all credentials of a given subject was signed by all required parties", async () => {
                (await issuer.verifyIssuedCredentials(subject1)).should.equal(true);
            });

            it("should return false if the credential is not approved", async () => {
                await issuer.registerCredential(subject2, digest3, constants.ZERO_BYTES32, [], { from: registrar1 });

                (await issuer.verifyCredential(subject2, digest3)).should.equal(false);
            });
        });

        describe("revert", () => {
            it("should revert if the credential does not exists", async () => {
                await expectRevert(
                    issuer.verifyCredential(subject1, digest3),
                    "Notary/credential not found"
                );
            });

            it("should revert if the credential is owned by the given subject", async () => {
                await expectRevert(
                    issuer.verifyCredential(subject2, digest1),
                    "Notary/not owned by subject"
                );
            });

            it("should revert if the is no credentials", async () => {
                await expectRevert(
                    issuer.verifyIssuedCredentials(subject2),
                    "Issuer/there are no credentials"
                );
            });
        });
    });

    describe("aggregate", () => {
        const digests = [digest1, digest2, digest3];

        beforeEach(async () => {
            issuer = await Issuer.new([registrar1], 1);
        });

        describe("normal behavior", () => {
            const expected = hashByteArray(digests);

            beforeEach(async () => {
                for (const d of digests) {
                    await issuer.registerCredential(subject1, d, constants.ZERO_BYTES32, [], { from: registrar1 });
                    await issuer.approveCredential(d, { from: subject1 });
                    await time.increase(time.duration.seconds(1));

                    (await issuer.isApproved(d)).should.equal(true);
                }
            });

            it("should aggregate all credentials of a subject", async () => {
                const aggregated = await issuer.aggregateCredentials.call(subject1, digests); // don't emit event
                (aggregated).should.equal(expected);
            });

            it("should successfully check whether a root exists", async () => {
                await issuer.aggregateCredentials(subject1, digests);
                (await issuer.hasRoot(subject1)).should.equal(true);
            });

            it("should return the already aggregated proof", async () => {
                await issuer.aggregateCredentials(subject1, digests);
                const storedProof = await issuer.getRoot(subject1);

                const aggregated = await issuer.aggregateCredentials.call(subject1, digests);

                (aggregated).should.equal(storedProof);
            });

            describe("events", () => {
                it("should emit an event when aggregate all credentials of a subject", async () => {
                    const { logs } = await issuer.aggregateCredentials(subject1, digests, { from: registrar1 });
                    const blockNumber = await time.latestBlock();
                    expectEvent.inLogs(logs, "AggregatedRoot", {
                        aggregator: registrar1,
                        subject: subject1,
                        proof: expected,
                        aggregatedBlock: blockNumber
                    });
                });
            });
        });

        describe("revert", () => {
            it("should fail if there are any credential of a subject that isn't signed by all parties", async () => {
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });

                await expectRevert(
                    issuer.aggregateCredentials(subject1, digests),
                    "Issuer/there are no credentials"
                );

                await issuer.approveCredential(digest1, { from: subject1 });
                (await issuer.isApproved(digest1)).should.equal(true);
            });

            it("should revert if there is no credential to be aggregated for a given subject", async () => {
                await expectRevert(
                    issuer.aggregateCredentials(subject1, digests),
                    "Issuer/there are no credentials"
                );
            });
        });

        it("should return the credential hash if only one credential exists", async () => {
            await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });
            await issuer.approveCredential(digest1, { from: subject1 });

            const aggregated = await issuer.aggregateCredentials.call(subject1, [digest1]);
            const expected = hashByteArray([digest1]);

            (aggregated).should.equal(expected);
        });
    });

    describe("verify aggregations", () => {
        const digests = [digest1, digest2, digest3];
        const expected = hashByteArray(digests);

        beforeEach(async () => {
            issuer = await Issuer.new([registrar1], 1);
        });

        describe("normal behaviour", () => {
            beforeEach(async () => {
                for (const d of digests) {
                    await issuer.registerCredential(subject1, d, constants.ZERO_BYTES32, [], { from: registrar1 });
                    await issuer.approveCredential(d, { from: subject1 });
                    await time.increase(time.duration.seconds(1));
                }
                await issuer.aggregateCredentials(subject1, digests);
            });

            it("should successfully verify the given credential", async () => {
                (await issuer.verifyCredentialRoot(subject1, expected)).should.equal(true);
            });

            it("should return false if given root does not match", async () => {
                (await issuer.verifyCredentialRoot(subject1, digest3)).should.equal(false);
            });
        });

        describe("revert", () => {
            it("should revert if there is no credentials to verify", async () => {
                await expectRevert(
                    issuer.verifyCredentialRoot(subject1, constants.ZERO_BYTES32),
                    "Issuer/there are no credentials"
                );
            });

            it("should revert if there is no root to be verified for a given subject", async () => {
                await issuer.registerCredential(subject1, digest1, constants.ZERO_BYTES32, [], { from: registrar1 });
                await issuer.approveCredential(digest1, { from: subject1 });
                await time.increase(time.duration.seconds(1));
                await expectRevert(
                    issuer.verifyCredentialRoot(subject1, constants.ZERO_BYTES32),
                    "CredentialSum/proof not exists"
                );
            });

            it("should revert if root proof does not exists", async () => {
                await expectRevert(
                    issuer.verifyRootOf(subject1, digests),
                    "CredentialSum/proof not exists"
                );
            });
        });
    });
});
