const { BN, constants, expectRevert, expectEvent } = require('@openzeppelin/test-helpers');
const { expect } = require('chai');

const Owners = artifacts.require('OwnersMock');

contract('Owners', accounts => {
    const [owner1, owner2, owner3] = accounts;
    let contract = null;

    describe('constructor', () => {
        it('should successfully deploy the contract', async () => {
            contract = await Owners.new([owner1, owner2], 2);
            (await contract.isOwner(owner1)).should.equal(true);
            (await contract.isOwner(owner2)).should.equal(true);
            expect(await contract.quorum()).to.be.bignumber.equal(new BN(2));
        });

        it('should require a non-empty array of owners', async () => {
            await expectRevert(Owners.new([], 0), 'Owners: not enough owners');
        });

        it('should require a quorum value greater than 0', async () => {
            await expectRevert(Owners.new([owner1], 0), 'Owners: quorum out of range');
        });

        it('should require a quorum value less than the amount of owners', async () => {
            await expectRevert(Owners.new([owner1, owner2], 3), 'Owners: quorum out of range');
        });

        it('should not allow duplicated owners addresses', async () => {
            await expectRevert.assertion(Owners.new([owner1, owner1], 2));
        });

        it('should not allow zero address for owner', async () => {
            await expectRevert.assertion(Owners.new([owner1, constants.ZERO_ADDRESS], 2));
        });
    });

    describe('change owner', () => {
        beforeEach(async () => {
            contract = await Owners.new([owner1, owner2], 2);
        });

        it('should successfully change an owner', async () => {
            (await contract.isOwner(owner1)).should.equal(true);
            (await contract.isOwner(owner2)).should.equal(true);
            (await contract.isOwner(owner3)).should.equal(false);
            expect(await contract.quorum()).to.be.bignumber.equal(new BN(2));

            await contract.changeOwner(owner3, { from: owner1 });

            (await contract.isOwner(owner1)).should.equal(false);
            (await contract.isOwner(owner2)).should.equal(true);
            (await contract.isOwner(owner3)).should.equal(true);
            expect(await contract.quorum()).to.be.bignumber.equal(new BN(2));
        });

        it('should revert if the list of owners is empty', async () => {
            await contract.deleteOwners();
            await expectRevert(contract.changeOwner(owner3, { from: owner1 }), "Owners: not enough owners");
        });


        it('should revert if the newOwner is already an owner', async () => {
            await expectRevert(contract.changeOwner(owner2, { from: owner1 }), "Owners: invalid address given");
        });


        it('should revert if the given address is invalid', async () => {
            await expectRevert(contract.changeOwner(constants.ZERO_ADDRESS, { from: owner1 }), "Owners: invalid address given");
        });

        it('should emit an event when changing owner', async () => {
            let { logs } = await contract.changeOwner(owner3, { from: owner1 })
            expectEvent.inLogs(logs, 'OwnerChanged', {
                oldOwner: owner1,
                newOwner: owner3
            });
        });
    });
});
