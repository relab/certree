const { BN, time, constants } = require('@openzeppelin/test-helpers');
const { toWei, fromWei } = require('web3-utils');

const Leaf = artifacts.require('LeafMock');
const Inner = artifacts.require('InnerMock');

async function deployLeaf(creator, owners) {
    let contract = await Leaf.new(owners, owners.length, { from: creator });
    return contract.address;
}

async function deployInner(creator, owners) {
    let contract = await Inner.new(owners, owners.length, { from: creator });
    return contract.address;
}

// returns { address: contractAddress, owners: ownersAddress[] }
async function createNotary(type, creator, owners) {
    let address;
    if (type == "leaf") {
        address = await deployLeaf(creator, owners);
    } else {
        address = await deployInner(creator, owners);
    }
    return { address: address, owners: owners };
}

// create a list of leaves based on the number of owners
// i.e. one leaf per owner
async function createLeaves(inner, innerOwner, leavesOwnersArray) {
    let leaves = [];
    for (owners of leavesOwnersArray) {
        let leaf = await createNotary("leaf", innerOwner, owners);
        await inner.addChild(leaf.address, { from: innerOwner });
        leaves.push(leaf);
    }
    return leaves
}

async function addNode(innerAddress, innerOwners, childrenAddress) {
    let nodeContract = await Inner.at(innerAddress);
    for (address of childrenAddress) {
        let { logs } = await nodeContract.addChild(address, { from: innerOwners[0] });
        let addr = (logs.find(e => e.event == "NodeAdded")).args.LeafAddress;
        (address).should.equal(addr);
    }
}

// @nodes: []object{ nodeAddress: []ownersAddress }
// @witnessesPerSubject: []object{ subjectAddress: []childAddress }
// @subjects: []subjectsAddress
// @n: int - number of credentials
// returns [{ address: witnessAddress, certs: [{ subject: subjectAddress, digests: bytes32[] }] }]
async function generateNodeCredentials(nodes, witnessesPerSubject, n) {
    let generatedNodes = [];
    for (inner of nodes) {
        let certsPerLeafBySubject = [];
        let nodeContract = await Inner.at(inner.address);
        for (w of witnessesPerSubject) {
            for (j = 0; j < n; j++) {
                let certificateDigest = web3.utils.keccak256(web3.utils.toHex(`NodeCertificate${i}-${j}@${inner.address}`));
                for (owner of inner.owners) {
                    await nodeContract.registerCredential(w.subject, certificateDigest, w.witnesses, { from: owner });
                    await time.increase(time.duration.seconds(1));
                }
                await nodeContract.confirmCredential(certificateDigest, { from: w.subject });
                await time.increase(time.duration.seconds(1));
                (await nodeContract.certified(certificateDigest)).should.equal(true);
            }
            let subjectCerts = await leafContract.digestsBySubject(w.subject);
            certsPerLeafBySubject.push({ subject: w.subject, digests: subjectCerts });
        };
        generatedNodes.push({ address: inner.address, certs: certsPerLeafBySubject });
    };
    return generatedNodes;
};

// returns contractAddress[]
async function getWitnesses(subject, contracts) {
    let witnesses = [];
    for (address of contracts) {
        let leafContract = await Leaf.at(address);
        let nonce = await leafContract.nonce(subject);
        // the subject have some credential issued in the contract
        if (nonce > 0) {
            witnesses.push(address);
        }
    }
    return witnesses;
}

// returns [{ subject: subjectAddress, witnesses: contractAddress[] }]
async function getAllWitnesses(subjects, contracts) {
    let witnesses = [];
    for (subject of subjects) {
        let w = getWitnesses(subject, contracts);
        if (w.length > 0) {
            witnesses.push({ subject: subject, witnesses: w });
        }
    }
    return witnesses;
}

// @leaves: []object{ contractAddress: []ownersAddress }
// @subjects: []subjectsAddress
// @n: int - number of credentials
// returns witness by subject by certs:
// { witnessAddress: { subjectAddress: bytes32[] } }
async function generateLeafCredentials(leaves, subjects, n) {
    let generatedLeaves = {};
    for (const leaf of leaves) {
        let certsPerLeafBySubject = {};
        let leafContract = await Leaf.at(leaf.address);
        for (i = 0; i < subjects.length; i++) {
            let subject = subjects[i];
            for (j = 0; j < n; j++) {
                let certificateDigest = web3.utils.keccak256(web3.utils.toHex(`LeafCertificate${i}-${j}@${leaf.address}`));
                for (owner of leaf.owners) {
                    await leafContract.registerCredential(subject, certificateDigest, [], { from: owner });
                    await time.increase(time.duration.seconds(1));
                }
                await leafContract.confirmCredential(certificateDigest, { from: subject });
                await time.increase(time.duration.seconds(1));
                (await leafContract.isApproved(certificateDigest)).should.equal(true);
            }
            let subjectCerts = await leafContract.getDigests(subject);
            certsPerLeafBySubject[subject] = subjectCerts;
        }
        generatedLeaves[leaf.address] = certsPerLeafBySubject;
    };
    return generatedLeaves;
};

// return hashByteArray(bytes32[]) performed by the contract
async function aggregateLeaf(leafContract, owner, subject, certs) {
    await leafContract.aggregateCredentials(subject, certs, { from: owner });
    return await leafContract.getRootProof(subject);
};

// returns [ hashByteArray(bytes32[]), bytes32[] ]
async function aggregateSubTree(witnesses, subject) {
    let rootPerLeaf = []; // evidences
    for (let [leaf, certsPerSubject] of Object.entries(witnesses)) {
        let leafContract = await Leaf.at(leaf);
        let leafOwners = await leafContract.owners();
        aggregation = await aggregateLeaf(leafContract, leafOwners[0], subject, certsPerSubject[subject]);
        rootPerLeaf.push(aggregation);
    }
    return [hashByteArray(rootPerLeaf), rootPerLeaf]; // [root, evidences]
};

// @witnesses: { witnessAddress: { subjectAddress: bytes32[] } }
// returns witness by subject by root:
// returns { witnessAddress: { subjectAddress: bytes32 } }
function computeSubTree(witnesses) {
    var rootPerWitness = {};
    for (let [w, certsPerSubject] of Object.entries(witnesses)) {
        var rootPerSubject = {};
        for (let [s, certs] of Object.entries(certsPerSubject)) {// aggregate all certs of witness w per subject
            rootPerSubject[s] = hashByteArray(certs);
        }
        rootPerWitness[w] = rootPerSubject;
    }
    return rootPerWitness;
}

function aggregationsOf(witnesses, subject) {
    roots = []
    for (let [w, rootPerSubject] of Object.entries(witnesses)) {
        if (w.hasOwnProperty(subject)) {
            roots.push(w[subject]);
        }
    }
    return roots;
}

function hash(data) {
    return web3.utils.keccak256(data);
}

function hashByteArray(byteArray) {
    return hash(web3.eth.abi.encodeParameter('bytes32[]', byteArray));
}

function etherToWei(amount) {
    return new BN(toWei(amount, 'ether'));
}

function weiToEther(amount) {
    return fromWei(amount, 'ether');
}

async function balance(address) {
    return new BN(await web3.eth.getBalance(address));
}

module.exports = {
    createNotary: createNotary,
    addNode: addNode,
    getAllWitnesses: getAllWitnesses,
    generateNodeCredentials: generateNodeCredentials,
    generateLeafCredentials: generateLeafCredentials,
    aggregateLeaf: aggregateLeaf,
    aggregateSubTree: aggregateSubTree,
    computeSubTree: computeSubTree,
    aggregationsOf: aggregationsOf,
    createLeaves: createLeaves,
    hash: hash,
    hashByteArray: hashByteArray,
    etherToWei: etherToWei,
    weiToEther: weiToEther,
    balance: balance
};