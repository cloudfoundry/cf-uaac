#!/usr/bin/env bash
token="$(uaac context | awk '/^ *access_token\: *([a-zA-Z0-9.\/+\-_]+) *$/ {print $2}' -)"
curl -H"Authorization: bearer $token" "$@"
