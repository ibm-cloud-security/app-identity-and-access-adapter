#!/bin/bash
#
# Copyright 2019 APP ID Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e
touch coverage.out

rootDir="$(dirname "${BASH_SOURCE[0]}")"/..

for d in $(go list ${rootDir}/adapter/...); do
    go test -coverprofile=profile.out -covermode=count ${d}
    if [[ -f profile.out ]]; then
        cat profile.out >> coverage.out
        rm profile.out
    fi
done