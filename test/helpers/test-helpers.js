const { time } = require('@openzeppelin/test-helpers');

const Issuer = artifacts.require('IssuerImpl');
const AccountableIssuer = artifacts.require('AccountableIssuerImpl');

async function createLeafIssuer(creator, owners) {
    let contract = await Issuer.new(owners, owners.length, { from: creator });
    return contract.address;
}

async function createNodeIssuer(creator, owners) {
    let contract = await AccountableIssuer.new(owners, owners.length, { from: creator });
    return contract.address;
}

// returns { address: contractAddress, owners: ownersAddress[] }
async function createNotary(type, creator, owners) {
    let address;
    if (type == "leaf") {
        address = await createLeafIssuer(creator, owners);
    } else {
        address = await createNodeIssuer(creator, owners);
    }
    return { address: address, owners: owners };
}

// create a list of leaves based on the number of owners
// i.e. one leaf per owner
async function createLeaves(acIssuer, acOwner, leavesOwners) {
    let leaves = [];
    for (owner of leavesOwners) {
        let issuerObj = await createNotary("leaf", acOwner, [owner]);
        await acIssuer.addIssuer(issuerObj.address, { from: acOwner });
        leaves.push(issuerObj);
    }
    return leaves
}

async function addNode(acIssuerAddress, acOwners, childrenAddress) {
    let nodeContract = await AccountableIssuer.at(acIssuerAddress);
    for (address of childrenAddress) {
        let { logs } = await nodeContract.addIssuer(address, { from: acOwners[0] });
        let addr = (logs.find(e => e.event == "IssuerAdded")).args.issuerAddress;
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
    for (acIssuer of nodes) {
        let certsPerIssuerBySubject = [];
        let nodeContract = await AccountableIssuer.at(acIssuer.address);
        for (w of witnessesPerSubject) {
            for (j = 0; j < n; j++) {
                let certificateDigest = web3.utils.keccak256(web3.utils.toHex(`NodeCertificate${i}-${j}@${acIssuer.address}`));
                for (owner of acIssuer.owners) {
                    await nodeContract.registerCredential(w.subject, certificateDigest, w.witnesses, { from: owner });
                    await time.increase(time.duration.seconds(1));
                }
                await nodeContract.confirmCredential(certificateDigest, { from: w.subject });
                await time.increase(time.duration.seconds(1));
                (await nodeContract.certified(certificateDigest)).should.equal(true);
            }
            let subjectCerts = await issuerContract.digestsBySubject(w.subject);
            certsPerIssuerBySubject.push({ subject: w.subject, digests: subjectCerts });
        };
        generatedNodes.push({ address: acIssuer.address, certs: certsPerIssuerBySubject });
    };
    return generatedNodes;
};

// returns contractAddress[]
async function getWitnesses(subject, contracts) {
    let witnesses = [];
    for (address of contracts) {
        let issuerContract = await Issuer.at(address);
        let nonce = await issuerContract.nonce(subject);
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
// returns [{ address: witnessAddress, certs: [{ subject: subjectAddress, digests: bytes32[] }] }]
async function generateLeafCredentials(leaves, subjects, n) {
    let generatedLeaves = [];
    for (const issuer of leaves) {
        let certsPerIssuerBySubject = [];
        let issuerContract = await Issuer.at(issuer.address);
        for (i = 0; i < subjects.length; i++) {
            let subject = subjects[i];
            for (j = 0; j < n; j++) {
                let certificateDigest = web3.utils.keccak256(web3.utils.toHex(`LeafCertificate${i}-${j}@${issuer.address}`));
                for (owner of issuer.owners) {
                    await issuerContract.registerCredential(subject, certificateDigest, { from: owner });
                    await time.increase(time.duration.seconds(1));
                }
                await issuerContract.confirmCredential(certificateDigest, { from: subject });
                await time.increase(time.duration.seconds(1));
                (await issuerContract.certified(certificateDigest)).should.equal(true);
            }
            let subjectCerts = await issuerContract.digestsBySubject(subject);
            certsPerIssuerBySubject.push({ subject: subject, digests: subjectCerts });
        }
        generatedLeaves.push({ address: issuer.address, certs: certsPerIssuerBySubject });
    };
    return generatedLeaves;
};

// return hashByteArray(bytes32[]) performed by the contract
async function aggregateLeaf(issuerContract, owner, subject) {
    await issuerContract.aggregateCredentials(subject, { from: owner });
    return await issuerContract.getProof(subject);
};

// returns [ hashByteArray(bytes32[]), bytes32[] ]
async function aggregateSubTree(rootContract, subject) {
    let rootPerIssuer = []; // evidences
    let issuerAddresses = await rootContract.issuers();
    for (i = 0; i < issuerAddresses.length; i++) {
        let issuerContract = await Issuer.at(issuerAddresses[i]);
        let issuerOwners = await issuerContract.owners();
        aggregation = await aggregateLeaf(issuerContract, issuerOwners[0], subject);
        rootPerIssuer.push(aggregation);
    }
    return [hashByteArray(rootPerIssuer), rootPerIssuer];
};

// @witnesses: [{ address: witnessAddress, certs: [{ subject: subjectAddress, digests: bytes32[] }] }]
// returns [{ address: witnessAddress, roots: [{ subject: subjectAddress, root: bytes32 }] }]
function computeSubTree(witnesses) {
    var rootPerWitness = [];
    for (w of witnesses) {
        var rootPerSubject = [];
        for (c of w.certs) { // aggregate all certs of witness w per subject
            rootPerSubject.push({ subject: c.subject, root: hashByteArray(c.digests) });
        }
        rootPerWitness.push({ address: w.address, roots: rootPerSubject });
    }
    return rootPerWitness;
}

function aggregationsOf(rootPerWitness, subject) {
    return rootPerWitness.map(w =>
        w.roots.filter(r => r.subject == subject)
            .map(c => c.root)).flat();
}

function hash(data) {
    return web3.utils.keccak256(data);
}

function hashByteArray(byteArray) {
    return hash(web3.eth.abi.encodeParameter('bytes32[]', byteArray));
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
    hashByteArray: hashByteArray
};