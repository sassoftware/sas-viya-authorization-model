#!/usr/bin/env bash

# Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

repo=${1:-'github.com/sassoftware/sas-viya-authorization-model'}
platformlist=${2:-'linux/amd64'}
version=${3:-'testbuild'}
package=${4:-'goviyaauth'}

IFS='|' read -ra platforms <<< "$platformlist"

for platform in "${platforms[@]}"
do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}
    output_name=$package'-'$GOOS'-'$GOARCH
    if [ $GOOS = "windows" ]; then
        output_name+='.exe'
    fi

    env GOOS=$GOOS GOARCH=$GOARCH go build -o build/$output_name -ldflags "-X $repo/cmd.Version=$version" $repo
    if [ $? -ne 0 ]; then
        echo 'An error has occurred! Aborting the script execution...'
        exit 1
    fi
done