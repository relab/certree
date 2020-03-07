# BBChain Contracts

Install and start a test chain.
```
npm install
npm run ganache-cli
```

In other terminal run the command below to run the contract tests.
```
npm test:ganache
```

If you prefer, you can use geth instead of [ganache](https://truffleframework.com/ganache) using the command below.
```
geth --networkid=42 --nodiscover \
     --rpc --rpcport=8545 --ws --wsport=8546 --rpccorsdomain="*" \
     --dev --dev.period 0 \
     --datadir=/<YOUR_PATH_TO>/devchain console 2>>dev.log
```