// https://github.com/chaijs/chai/pull/868
// Using Should style globally
require('chai/register-should');

const fs = require('fs');
const HDWalletProvider = require("@truffle/hdwallet-provider");

const envFile = ".env";
let mnemonic = null;
let infura_project_id = null;
let coinmarketcap_apikey = "";
let data = fs.readFileSync(envFile, 'utf8');

function parseEnv(param) {
    var regex = new RegExp(param + "=", "i");
    let match = data.split('\n').find(line => regex.test(line));
    if (match) {
        return match.split("=")[1];
    }
    throw new Error("ERROR: Environment variable " + param + " not found on file .env and ROPSTEN_TESTNET is set to " + process.env.ROPSTEN_TESTNET);
};

if (process.env.ROPSTEN_TESTNET) {
    mnemonic = parseEnv("MNEMONIC");
    infura_project_id = parseEnv("INFURA_PROJECT_ID");
}

if (process.env.GAS_REPORT) {
    coinmarketcap_apikey = parseEnv("COINMARKETCAP_APIKEY");
}

module.exports = {
    networks: {
        development: { // local test net
            host: "127.0.0.1",
            port: 8545,
            network_id: "*" // eslint-disable-line camelcase
        },
        ganache: { // ganache-cli
            host: "127.0.0.1",
            port: 7545,
            network_id: "5777" // eslint-disable-line camelcase
        },
        develop: { // truffle development
            host: "127.0.0.1",
            port: 8545,
            network_id: "*", // eslint-disable-line camelcase
            accounts: 5,
            defaultEtherBalance: 50
        },
        ropsten: { // ropsten testnet
            provider: function () {
                return new HDWalletProvider(mnemonic, `https://ropsten.infura.io/v3/${infura_project_id}`, 0, 10, true, "m/44'/60'/0'/0/");
            },
            network_id: "3", // eslint-disable-line camelcase
        },
    },

    mocha: {
        // timeout: 100000,
        useColors: true,
        reporter: 'eth-gas-reporter',
        reporterOptions: {
            currency: 'USD', // NOK, EUR
            src: "contracts",
            showMethodSig: true,
            outputFile: "gas-report.txt",
            onlyCalledMethods: true,
            showTimeSpent: true,
            excludeContracts: ['Migrations'],
            coinmarketcap: coinmarketcap_apikey
        }
    },

    plugins: ["solidity-coverage"],

    compilers: {
        solc: {
            version: '0.8.2',
            settings: {
                optimizer: {
                    enabled: true,
                    runs: 100
                },
                outputSelection: {
                    "*": {
                        "*": [
                            "metadata",
                            "abi",
                            "evm.bytecode.object",
                            "evm.bytecode.sourceMap",
                            "evm.deployedBytecode.object",
                            "evm.deployedBytecode.sourceMap"
                        ],
                        "": ["ast"],
                    }
                },
                evmVersion: "petersburg"
            }
        }
    }
};
