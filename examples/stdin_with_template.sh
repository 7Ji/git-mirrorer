#!/bin/bash
# To create archive/checkout by feeding config into git-mirrorer's stdin
# Especially useful for repos with submodules

TEMPLATE='
repos:
  - %s:
      wanted:
        - %s:
            type: commit
            archive: yes
            checkout: yes
archive:
  suffix: .tar.zst
  pipe_through: zstd -22 --ultra
  github_like_prefix: yes
cleanup:
  repos: yes
  archives: yes
  checkouts: yes
'

if [[ $# -lt 4 ]]; then
  echo './stdin_with_template.sh [REPO URL] [COMMIT ID] [ARCHIVE OUT] [CHECKOUT OUT]'
  exit 1
fi

REPO=$1
COMMIT=$2
ARCHIVE=$3
CHECKOUT=$4

rm -rf ${ARCHIVE} ${CHECKOUT}

if ! printf "${TEMPLATE}" "${REPO}" "${COMMIT}" | tee | ./git-mirrorer; then
  echo 'Failed to export'
  exit 1
fi

mv archives/${COMMIT}.tar.zst ${ARCHIVE}
mv checkouts/${COMMIT} ${CHECKOUT}