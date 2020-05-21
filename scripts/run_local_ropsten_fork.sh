#!/bin/bash

infura_project_id=$(grep INFURA_PROJECT_ID .env | cut -d '=' -f2)
mnemonic=$(grep MNEMONIC .env | cut -d '=' -f2)
ganache-cli --fork https://mainnet.infura.io/v3/${infura_project_id} --networkId 3 --mnemonic "${mnemonic}" --noVMErrorsOnRPCResponse