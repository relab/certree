// Taken from: https://github.com/OpenZeppelin/openzeppelin-test-helpers/blob/master/test/helpers/assertFailure.js

const { expect } = require('chai');

async function assertFailure(promise) {
    try {
        await promise;
    } catch (error) {
        return error;
    }
    expect.fail();
}

module.exports = assertFailure;