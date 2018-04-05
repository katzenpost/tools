#!/bin/sh
docker build -f authority.dockerfile -t authority .
docker build -f server.dockerfile -t server .
# extract binaries to local filesystem
IMG_ID=$(cat ../.git/refs/heads/master)

docker create --name ${IMG_ID} authority
docker cp ${IMG_ID}:nonvoting .
docker rm ${IMG_ID}

docker create --name ${IMG_ID} server
docker cp ${IMG_ID}:server .
docker rm ${IMG_ID}
