#!/bin/bash -e
# To fetch dependencies if you're building on a non-arch environment

#
dep_names=(
  'yaml-0.2.5'
  'xxhash-0.8.2'
  'libgit2-1.7.1'
  'libgit2-1.7.0-git_oidarray_include.patch'
  'libgit2-1.7.0-cleanup_grafts.patch'
)
dep_dlnames=(
  "${dep_names[0]}.tar.gz"
  "${dep_names[1]}.tar.gz"
  "${dep_names[2]}.tar.gz"
  "${dep_names[3]}"
  "${dep_names[4]}"
)
dep_urls=(
  "https://pyyaml.org/download/libyaml/${dep_dlnames[0]}"
  'https://github.com/Cyan4973/xxHash/archive/bbb27a5efb85b92a0486cf361a8635715a53f6ba.tar.gz'
  'https://github.com/libgit2/libgit2/archive/3e2baa6d0bfb42f9016e24cba1733a6ae26a8ae6.tar.gz'
  'https://gitlab.archlinux.org/archlinux/packaging/packages/libgit2/-/raw/e84d2778de5936988f34e2d6bbc46105d4a1e9e9/libgit2-1.7.0-git_oidarray_include.patch'
  'https://github.com/libgit2/libgit2/commit/9d4c550564ee254dda9e2620c4c1e32ebb529728.patch'
)
dep_sha256sums=(
  'c642ae9b75fee120b2d96c712538bd2cf283228d2337df2cf2988e3c02678ef4'
  '716fbe4fc85ecd36488afbbc635b59b5ab6aba5ed3b69d4a32a46eae5a453d38'
  'b28c20c868a82f4d933c0cf3a3afeb6d6ea08932e77a50b969a2040b201b4d6c'
  'b4a4897fd376ee94e30f3d695194614062fc87ec22ccb249c86d71afbc2c5d92'
  '1c921387370c10a08d8db0143b70f94be205cc1e4af7faf3626f673d244747da'
)
dep_patches=(
  ''
  ''
  '3 4'
  ''
  ''
)

# Download
downloaded=''
mkdir -p deps
i=0
for dep_dlname in "${dep_dlnames[@]}"; do
  if [[ ! -f deps/${dep_dlname} ]]; then
    wget -O deps/"${dep_dlname}" "${dep_urls[$i]}"
    downloaded='yes'
  fi
  let ++i
done
# Integrity check
if [[ "${downloaded}" ]]; then
  verify_sha256sums=$(
    i=0
    for dep_dlname in "${dep_dlnames[@]}"; do
      echo "${dep_sha256sums[$i]}  deps/${dep_dlname}"
      let ++i
    done
  )
  sha256sum --check <(printf "$verify_sha256sums")
fi
# Extracting
i=0
for dep_name in "${dep_names[@]}"; do
  [[ -e "deps/${dep_name}" ]] && continue
  if [[ "${dep_dlnames[$i]}" == "${dep_name}" ]]; then
    cp -av "deps/${dep_dlnames[$i]}" "deps/${dep_dlname}"
  else
    mkdir -p "deps/${dep_name}"
    tar -C "deps/${dep_name}" -xf "deps/${dep_dlnames[$i]}" --strip-components=1
    if [[ "${dep_patches[$i]}" ]]; then
      pushd "deps/${dep_name}"
      for dep_patch in ${dep_patches[$i]}; do
        patch -Np1 -i ../${dep_names[${dep_patch}]}
      done
      popd
    fi
  fi
  let ++i
done