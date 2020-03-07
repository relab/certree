const { constants, expectRevert } = require('@openzeppelin/test-helpers');
const Owners = artifacts.require('Owners');

contract('Owners', accounts => {
    const [owner1, owner2] = accounts;
    let contract = null;

    describe('constructor', () => {
        it('should successfully deploy the contract', async () => {
            contract = await Owners.new([owner1, owner2], 2);
            (await contract.isOwner(owner1)).should.equal(true);
            (await contract.isOwner(owner2)).should.equal(true);
            assert(contract.quorum(), 2);
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
});
