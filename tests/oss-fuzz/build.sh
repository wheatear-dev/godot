#!/bin/sh

# build up the root .dockerignore
cat tests/oss-fuzz/.dockerignore > .dockerignore
cat .gitignore | sed 's|^/||' >> .dockerignore

# build the docker image
docker build --platform linux/amd64 -f tests/oss-fuzz/Dockerfile .
