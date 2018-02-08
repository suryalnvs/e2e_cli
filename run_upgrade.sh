#!/bin/bash

echo "Launching network with v1.0.3"
export IMAGE_TAG=x86_64-1.0.3
export SCRIPT=script.sh
./network_setup.sh up

sleep 10

docker rm -f orderer.example.com peer0.org1.example.com peer1.org1.example.com peer0.org2.example.com peer1.org2.example.com cli dev-peer0.org1.example.com-mycc-1.0 dev-peer0.org2.example.com-mycc-1.0 dev-peer1.org2.example.com-mycc-1.0
docker rmi -f $(docker images | grep "dev\|none\|test-vp\|peer[0-9]-" | awk '{print $3}')
export IMAGE_TAG=latest
export SCRIPT=script_upgrade.sh
docker-compose -f docker-compose-e2e.yaml up -d orderer.example.com peer0.org1.example.com peer1.org1.example.com peer0.org2.example.com peer1.org2.example.com cli
