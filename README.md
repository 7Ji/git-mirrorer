# git-mirrorer
To **mirror**, **archive** and **checkout** git repos **even across submodules**.


# Usage
## Basic
To let `git-mirrorer` mirror a list of repos, simply define them in a `.yaml` config file, and then pass the file to it via `--config [file]`, or feed the config into its stdin.

You can start from a simple config file like the following:
```
repos:
  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
  - https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
```
After `./git-mirrorer --config config.yaml`, you will have the following directory structure:
```
repos
├── 2c7adc93616e76cd/
├── 672b80351731823c/
└── links
    └── git.kernel.org
        └── pub
            └── scm
                └── linux
                    └── kernel
                        └── git
                            ├── stable
                            │   └── linux.git-> ../../../../../../../../672b80351731823c
                            └── torvalds
                                └── linux.git-> ../../../../../../../../2c7adc93616e76cd
```
_`git-mirrorer` uses 64-bit XXHash 3 to generate local repo names from the url, the above `2c7adc93616e76cd` and `672b80351731823c` are such examples. There will also be symlinks created under `repos/links` which is easier to lookup for humans._

You can then clone/fetch from your local copies under `repos/`. You can also expose either `repos/` or `repos/links/` as the root of your git deamon and then clone/fetch from the local mirror across your lan/Internet.

## Daemon
By default, `git-mirrorer` will only run once before quiting. However, it also has a built-in daemon mode that will run forever until error encountered. You can config it like the following:
```
daemon: yes
daemon_interval: 10
repos:
  ...... #(omitted)
```
#### `daemon`
Controls whether `git-mirrorer` runs in **daemon mode** (if set to `yes`) or **oneshot mode** (default, if set to `no`).

#### `daemon_interval`
The interval (in second) `git-mirrorer` should sleep between each work cycle, default is 60 (i.e. 1 min).

#### Config watch
Exclusive to daemon mode, if you define the config on command-line with `--config [file]` argument, `git-mirrorer` will watch on any update on the config file, and re-read the config at the end of each work cycle. 

You don't need to worry about a bad config update breaking the program, as `git-mirrorer` will only switch to the new config if it is valid.

Additionally, updating `daemon` to `no` while `git-mirrorer` is running in daemon mode will not make `git-mirrorer` switch to oneshot mode, and a restart is needed if you really want to do that.

## Wanted objects
If you run `git-mirrorer` with only a simple repos list, you might read the following log:
```
[WARN] Repo 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git' does not have wanted objects defined, adding global wanted objects (when empty) to it as wanted
```
A wanted object is what you can define for repos that can be parsed into commits that should be **robust** _(at least existing, in `git-mirrorer` **robust** means more than existing, read the [following section](#submodules) for more info)_. They can either be defined for a repo, or globally.

A list of wanted object for repo can be defined like this:
```
repos:
  - https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git:
      wanted:
        - v6.4.10
        - v6.4.9
```
_Here `v6.4.10` and `v6.4.9` will be parsed automatically as wanted tags, and during mirroring, `git-mirrorer` will ensure they can be parsed into commits, and the commits are **robust**_

Two lists of wanted object can also be defined globally:
```
wanted:
  empty:
    - HEAD
  always:
    - all_tags
repos:
  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
  - https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git:
      wanted:
        - v6.4.10
        - v6.4.9
```
The global `empty` wanted list will be added to repos that don't have their wanted list defined, and `always` wanted list will be added to all repos.

By default, the global `empty` wanted list has a single `HEAD` wanted object in it, defining your own global `empty` will overwrite it.

The following types of wanted objects are supported:
 - commit _(e.g. `01490fd87eb650ca654ce811af42c7a77c174324`)_
 - HEAD
 - branch _(e.g. `main`)_
 - tag _(e.g. `v1.0`)_
 - reference _(e.g. `refs/heads/master`)_
 - all_branches _(expanded to a series of wanted branches at run time)_
 - all_tags _(expanded to a series of wanted references at run time)_

You can manually set the type of a wanted object if `git-mirrorer` can't guess it from the name, or guess it wrong, e.g. :
```
# This looks like a tag, but it's used as a branch name in stable/linux
v6.1.y: 
  type: branch
```

Note that `git-mirrorer` updates repos **lazily**, that is, unless there's any wanted object that is not directly a commit, or any commit that does not exist locally, `git-mirrorer` won't update the repo. Adding any wanted object that's not a commit will cause `git-mirrorer` update the repo. The default global `empty` wanted object `HEAD` is one such example.

## Submodules
For any wanted object, if it can be parsed into a commit, `git-mirrorer` will ensure its **robustness** across all of its submodules recursively. That is, every repo configured recursively as a submodule will be added virtually to the repo list, then **lazily** updated to ensure the commit wanted by the parent is also **robust**, until a complete tree can be created from pure local repos.

_Such **robustness** is what makes the function in [next section](#exporting) possible_

An example run with the following repo list:
```
repos:
  - https://github.com/yuzu-emu/yuzu.git
```
Will result in the following directory structure:
```
repos
├── 002536ab13f83fe4/
├── 00d56e0167c0a9c5/
├── 18a62faab712628e/
├── 197d5690289065db/
├── 2c251c035f9cad01/
├── 3448bd3db493b60d/
├── 3b06bd242afbf04e/
├── 4da79a9d01fb6196/
├── 61741072ad91123c/
├── 62a854c56c1b2a8e/
├── 67f763e658bca3c7/
├── 7d09248f4ea2b698/
├── 8b8ab2277ad56010/
├── 8ba2d45bd2a8eb11/
├── 8c027578b52a1287/
├── 97ac52e9ede5597d/
├── a8a25d8b3fbd3705/
├── ac530d68aae02987/
├── bbb3f3e343238340/
├── ccce874087ac136b/
├── dcad775dbe0c7583/
├── e0daf456084f46c5/
├── e93e58c63a6ee116/
├── ee4cd45ed2537880/
├── f66a7e73ec174822/
└── links
    └── github.com
        ├── arsenm
        │   └── sanitizers-cmake -> ../../../e0daf456084f46c5
        ├── arun11299
        │   └── cpp-jwt.git -> ../../../8c027578b52a1287
        ├── benhoyt
        │   └── inih.git -> ../../../97ac52e9ede5597d
        ├── bylaws
        │   ├── libadrenotools.git -> ../../../8b8ab2277ad56010
        │   └── liblinkernsbypass -> ../../../3b06bd242afbf04e
        ├── eggert
        │   └── tz.git -> ../../../ee4cd45ed2537880
        ├── FFmpeg
        │   └── FFmpeg.git -> ../../../8ba2d45bd2a8eb11
        ├── google
        │   └── googletest -> ../../../67f763e658bca3c7
        ├── GPUOpen-LibrariesAndSDKs
        │   └── VulkanMemoryAllocator.git -> ../../../ccce874087ac136b
        ├── herumi
        │   └── xbyak.git -> ../../../18a62faab712628e
        ├── KhronosGroup
        │   ├── SPIRV-Headers -> ../../../2c251c035f9cad01
        │   └── Vulkan-Headers.git -> ../../../7d09248f4ea2b698
        ├── lat9nq
        │   └── tzdb_to_nx.git -> ../../../61741072ad91123c
        ├── libsdl-org
        │   └── SDL.git -> ../../../002536ab13f83fe4
        ├── libusb
        │   └── libusb.git -> ../../../197d5690289065db
        ├── lsalzman
        │   └── enet.git -> ../../../e93e58c63a6ee116
        ├── merryhime
        │   └── dynarmic.git -> ../../../00d56e0167c0a9c5
        ├── microsoft
        │   └── vcpkg.git -> ../../../dcad775dbe0c7583
        ├── mozilla
        │   └── cubeb.git -> ../../../3448bd3db493b60d
        ├── xiph
        │   └── opus.git -> ../../../a8a25d8b3fbd3705
        ├── yhirose
        │   └── cpp-httplib.git -> ../../../f66a7e73ec174822
        └── yuzu-emu
            ├── discord-rpc.git -> ../../../ac530d68aae02987
            ├── mbedtls.git -> ../../../62a854c56c1b2a8e
            ├── sirit.git -> ../../../4da79a9d01fb6196
            └── yuzu.git -> ../../../bbb3f3e343238340
```
All of the additional repos are cloned as they're either directly referenced as submodules in `yuzu.git`, or indirectly as recursive submodules as `yuzu.git`'s submodule. And the **robustness** of both `yuzu.git`'s `HEAD` commit and all other repos' commit referenced by any submodule are ensured. It is with this **robustness** that the [following section](#exporting) is possible.

## Exporting
For every wanted object, you can export it as either `archive` or `checkout`, in both case they will contain all recursively submodules:
```
repos:
  - https://github.com/yuzu-emu/yuzu.git:
      wanted:
        - all_tags:
            archive: yes
            checkout: yes
        - all_branches:
            archive: yes
            checkout: yes
```
After a run with the above config, you will have a tree structure like the following:
```
archives/
├── 26ff2147197352b571c394404de2be1a65d0cf9b.tar
└── links
    └── github.com
        └── yuzu-emu
            └── yuzu.git
                ├── 26ff2147197352b571c394404de2be1a65d0cf9b.tar -> ../../../../26ff2147197352b571c394404de2be1a65d0cf9b.tar
                ├── branches -> refs/heads
                └── refs
                    └── heads
                        └── master.tar -> ../../../../../../26ff2147197352b571c394404de2be1a65d0cf9b.tar
```
The file `archives/26ff2147197352b571c394404de2be1a65d0cf9b.tar` would contain all of the content existing at `yuzu.git`'s that commit, **including submodules**; 
```
checkouts/
├── 26ff2147197352b571c394404de2be1a65d0cf9b/
└── links
    └── github.com
        └── yuzu-emu
            └── yuzu.git
                ├── 26ff2147197352b571c394404de2be1a65d0cf9b -> ../../../../26ff2147197352b571c394404de2be1a65d0cf9b
                ├── branches -> refs/heads
                └── refs
                    └── heads
                        └── master -> ../../../../../../26ff2147197352b571c394404de2be1a65d0cf9b
```

Likewise, the folder `checkouts/26ff2147197352b571c394404de2be1a65d0cf9b` would also contain all of the content existing at `yuzu.git`'s that commit, **including submodules**. 

In both cases the submodules are stored as if they're plain folders in the parent git tree, which is not supported by `git`'s own archiving functionality, or platforms like Github, Gitlab, etc. E.g.
```
> ls checkouts/26ff2147197352b571c394404de2be1a65d0cf9b/externals/cubeb/cmake/sanitizers-cmake/
cmake/  CMakeLists.txt  LICENSE  README.md  tests/
```
You can see that the submodule `externals/cubeb` 's submodule `cmake/sanitizers-cmake` exists with all of its content under the super project as `externals/cubeb/cmake/sanitizers-cmake`, which also applies to archives.

Do note that the `checkout`s here are really just `checkout`s, they're not `clone`s as there's no existing `.git` folder or file under the tree.

You can then export either `archives`, `archives/links`, `checkouts`, `checkouts/links` to network to serve them.

### Archive advanced config
There're some global configs for archives that can be set, a quick example:
```
archive:
  suffix: .tar.zst
  github_like_prefix: yes
  pipe_through: 'zstd -22T0 --ultra'
```
Like in the above example:
#### `suffix`
Controls the suffix to be appended to the archives' names, the default value is `.tar`.  
Note it **does not affect the actual format**, the actual format that `git-mirrorer` natively generates is always **GNU tar stream**.   
I.e. setting this to `.tar.zst` **only changes the suffix** but **does not** automatically make the output stream a `zstd compressed data` stream.
#### `github_like_prefix`
When configured to `yes`, every entry in the archive will have a `[repo short name]-[commit hash]/` prefix.   
By default this is set to `no` and every entry is directly in the archive's root, e.g. `README.md` in that `yuzu.git` archive is stored as `README.md` in the archive. If set to `yes` then it is stored as `yuzu-26ff2147197352b571c394404de2be1a65d0cf9b/README.md`.  
Setting this to `yes` might be helpful for your existing building routine if it expects such prefix.
#### `pipe_through`
Defines a program and its argument which the original **GNU tar** stream would go through, and that program would now control the **actual output format**. By default this is empty so the archive format is `tar`.  
The recommendation is to set a compressor but you're free to use anything that eats stdin and outputs to stdout.  
Alternatively `pipe-through` can be set as a list, this is especially useful if your arguments include whitespace, e.g.:
  ```
  pipe_through:
    - sh
    - -c
    - gzip -9 | bzip2 -9 | xz -9e | zstd -22T0 --ultra
  ```
  _Piping a lot of different compressors does not result in better compression and it is very stupid. Plz don't really do it like this : )_

#### Conclusion
You might find it strange at first that `git-mirrorer` does not outputs `.tar.gz` compressed archives directly, but only `.tar` archives. But now you should understand that, with the freedom to combine any archive suffix and any piper, `git-mirrorer` can essentially create archives that's compressed in **any format**.


## Cleaning
As `git-mirrorer` ensures the **robustness** of the wanted objects it fetches all of the repos that're referenced either directly or indirectly in the commits resolved from those wanted objects, **for every run**. Your `repos` folder might become larger and larger as you run `git-mirrorer` again and again to keep the repos up-to-date. The same applies to `archives` and `checkouts` if the wanted objects are dynamic and they point to new commits as you update the repos. 

By default `git-mirrorer` does not clean those folders but only the dead symlinks under `[repos/archives/checkouts]/links`, but you can set the following config to change its behaviour:

```
cleanup:
  repos: yes
  archives: yes
  checkouts: yes
```
After repos are mirrored and needed archives/checkouts are created, `git-mirrorer` will delete any entry that's not needed under the corresponding folder to release the space.

Note: turning on cleanup would eat extra performance as an in-memory keeps list would need to be maintained and it must be sorted before the actual cleaning. You might also want those repos/archives/checkouts for data hoarding purposes.

## Threading
`git-mirrorer` does multi-threading in the following stages:
 - When updating the repos
 - When exporting the commits

By default there're at most 10 connections allowed to each server, each repo a connection, the total updating threads are indirectly limited by this; and at most 10 threads exporting the commits.

The following global config can change the behaviour, both are non-negative integers:
```
connections_per_server: 10
export_threads: 10
```
#### `connections_per_server`
The total update threads we can create and thus the connections count we can open to a server. The limit is applied independent of the protocol, e.g. `git://github.com/userA/repoB.git` and `https://github.com/userC/repoD.git` are considered to have the same server `github.com`, while `https://git.kernel.org/xxxx` has a different server `git.kernel.org`

Do not set this too high as that would put heavy load on the remote server and it would probably consider your're DDoSing and ban you as a result.

You could have more total update threads than this limit if you have repos from different servers, but that threads count can't be directly limited, as I don't think there're that many different git servers you want to mirror from.

By default this is set to 10, setting it to 0 would disable the multi-threaded updating, but setting it to 1 would not if there're repos from multiple servers.

#### `export_threads`
The total exporting threads. For a single wanted object, the archive and checkout exporting jobs are done in the **same** thread to reduce overhead. So the amount of exporting threads is the amount of wanted objects that's being exported.

You might want to increase/decrease the exporting threads limit depending on whether if you're bottlenecked by CPU / RAM / Disk I/O.

By default this is set to 10, setting it to 0 or 1 would disable the multi-threaded exporting completely.

Note the external program you define in `archive/pipe_through` is not limited by this. You'll need to reduce this if you run some heavy compressor, or you set those compressor to run in multi-threading mode.

## Proxy
A http proxy can be configured globally, but it only affects repos using `http/https` protocol, e.g.
```
proxy: http://you_http_proxy
```
Addtionally, you can set `proxy_after` to make `git-mirrorer` only use the proxy after a certain number of failures, so you can save bandwidth of proxy if you still have connection to the remove server that's just not stable enough:
```
proxy_after: 3
```
`proxy_after` is a non-negative interger and it adds up to the total retry count. The default value is `0`, and `git-mirrorer` will try 3 times with proxy, while in the above example `git-mirrorer` will try 3 times without proxy and 3 times with proxy.

It is also possible to set this to a very large number so `git-mirrorer` will retry forever and never bail out due to failed connection.

## stdin advanced usage
`git-mirrorer` can also read config from stdin, this makes it ideal to be embedded into a build system to handle the .git source, especially those with submodules.

You can keep a system-wide config template like following:
```
dir_repos: /var/cache/repos
dir_checkouts: %s
links: no
repos:
  - %s:
      wanted:
        - %s:
            type: commit
            checkout: yes
```

And then you can pipe the parsed config to `git-mirrorer` on command-line to checkout the repo:
```
BUILD_DIR=xxxxx
printf $(cat config.template) "$CHECKOUT_DIR" "$REPO_URL" "$COMMIT_ID" | ./git_mirrorer
mv "$CHECKOUT_DIR/$COMMIT_ID" "$BUILD_DIR"
```


## Build
The following libraries are needed on your host:
 - xxhash _(0.8.2)_
 - libgit2 _(1.7.1)_
 - libyaml _(0.2.5)_

If you're building in the git tree `git` is also needed to generate the version info.

---
On Arch (the distro I'm using, and developed `git-mirrorer` on) the dependencies could be installed simply with the following command:
```
sudo pacman -Syu base-devel xxhash libgit2 libyaml
```

When the dependencies are all installed, just run `make` in the folder you're reading this `README.md`, the result binary would be `git-mirrorer`. 

---

On Debian-based distros, these dependencies could be installed via the following command:
```
sudo apt update
sudo apt install build-essential libyaml-dev libgit2-dev libxxhash-dev
```
**However, at least on Ubuntu 22.04 Jammy that I've tested, libgit2 is dramatically outdated (at v1.1.0), the package thus can't be linked to the system-provided `libgit2`**

An alternative build method, mainly for such systems, is to run the following build command, which will fetch these libraries and build them seperately from the system. Addtionally, the following dependencies are needed:
```
sudo apt install cmake libpcre2-dev libhttp-parser-dev libssh2-1-dev
```
Use the following comamnd to build with bundled libraries:

```
make BUILD_DEPS=1
```

To run `git-mirrorer` built in this way you'll need to preload the libraries:
```
LD_LIBRARY_PATH=lib ./git-mirrorer
```


## License
**git-mirrorer**, to mirror, archive and checkout git repos even across submodules

Copyright (C) 2023-present Guoxin "7Ji" Pu

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

## Know limitations
Currently the tool does not support any repo that needs authentication (e.g. repos over `SSH`, or github private repos over `https`). I'm not planning to support this, as the main focus of the tool is to mirror public repos.

Also, as this is using libgit2, the only proxy type that's supported is http proxy.