#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

docker build -t "theenbyperor/wwfypc-abc:$VERSION" . || exit
docker push "theenbyperor/wwfypc-abc:$VERSION" || exit

sentry-cli releases --org we-will-fix-your-pc new -p abc-proxy $VERSION || exit
sentry-cli releases --org we-will-fix-your-pc set-commits --auto $VERSION
