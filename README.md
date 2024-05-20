# git-mirrorer
To **mirror** git repos, and **archive** and **checkout** them with submodules included implicitly.

# Usage
## Basic
To let `git-mirrorer` mirror a list of repos, simply define them in a `.yaml` config file, and then pass the file to it via `--config [file]`, or feed the config into its stdin.

You can start from a simple config file like the following:
```
repos:
  - https://github.com/yuzu-emu/yuzu
```
After `./git-mirrorer --config config.yaml`, you will have the following directory structure:
```
repos
├── data
│   ├── 207453df7ad0862c
│   ├── 23ebb7fc06308e86
│   ├── 2c251c035f9cad01
│   ├── 37192ff591219eb8
│   ├── 3af9c204e8e472ca
│   ├── 3b751f23ac239671
│   ├── 3db66e36cd9d329c
│   ├── 4f5d1267939148d1
│   ├── 67f763e658bca3c7
│   ├── 706cc75c68042f9e
│   ├── 899f84800b55451a
│   ├── 8dbac069a5094020
│   ├── 969ac173416c0008
│   ├── 9a0c678726caecc0
│   ├── 9d229421bcd5dac9
│   ├── 9e57cbc12dbad75b
│   ├── b57e0f2784d3b943
│   ├── b693c4422be4000f
│   ├── c39f2cfc27b16fac
│   ├── c483e6ab7741f51b
│   ├── c8f9f0009912835e
│   ├── d955bd8fbfab8532
│   ├── e0daf456084f46c5
│   ├── eb478c30d4abecc8
│   └── f15c7e135413006f
└── links
    └── github.com
        ├── arsenm
        │   └── sanitizers-cmake.git -> ../../../data/e0daf456084f46c5
        ├── arun11299
        │   └── cpp-jwt.git -> ../../../data/4f5d1267939148d1
        ├── benhoyt
        │   └── inih.git -> ../../../data/37192ff591219eb8
        ├── bylaws
        │   ├── libadrenotools.git -> ../../../data/9e57cbc12dbad75b
        │   └── liblinkernsbypass.git -> ../../../data/969ac173416c0008
        ├── eggert
        │   └── tz.git -> ../../../data/3db66e36cd9d329c
        ├── FFmpeg
        │   └── FFmpeg.git -> ../../../data/899f84800b55451a
        ├── google
        │   └── googletest.git -> ../../../data/67f763e658bca3c7
        ├── GPUOpen-LibrariesAndSDKs
        │   └── VulkanMemoryAllocator.git -> ../../../data/d955bd8fbfab8532
        ├── herumi
        │   └── xbyak.git -> ../../../data/9a0c678726caecc0
        ├── KhronosGroup
        │   ├── SPIRV-Headers.git -> ../../../data/2c251c035f9cad01
        │   └── Vulkan-Headers.git -> ../../../data/8dbac069a5094020
        ├── lat9nq
        │   └── tzdb_to_nx.git -> ../../../data/f15c7e135413006f
        ├── libsdl-org
        │   └── SDL.git -> ../../../data/b693c4422be4000f
        ├── libusb
        │   └── libusb.git -> ../../../data/706cc75c68042f9e
        ├── lsalzman
        │   └── enet.git -> ../../../data/9d229421bcd5dac9
        ├── merryhime
        │   └── dynarmic.git -> ../../../data/c483e6ab7741f51b
        ├── microsoft
        │   └── vcpkg.git -> ../../../data/207453df7ad0862c
        ├── mozilla
        │   └── cubeb.git -> ../../../data/c39f2cfc27b16fac
        ├── xiph
        │   └── opus.git -> ../../../data/3af9c204e8e472ca
        ├── yhirose
        │   └── cpp-httplib.git -> ../../../data/c8f9f0009912835e
        └── yuzu-emu
            ├── discord-rpc.git -> ../../../data/eb478c30d4abecc8
            ├── mbedtls.git -> ../../../data/b57e0f2784d3b943
            ├── sirit.git -> ../../../data/23ebb7fc06308e86
            └── yuzu.git -> ../../../data/3b751f23ac239671
```

The structure is populated with the following logic for any remote repo that needs to be mirrored:
 1. `git-mirrorer` would mirror it into `repos/data/[HASH]`, where the `[HASH]` is unique for any given URL. This automatically avoids the problem where multiple remote repos share the same name.
 2. `git-mirrorer` would mirror any other repos that are referenced in the defined repos as submodules, so a complete repo tree could be constructed using only own local repos. By default only the HEAD commit of your defined repos are parsed like this.
 3. `git-mirrorer` would create symlinks under `repos/links` with paths composed of their URL segments pointing to the actual repos, so you can easily clone from `git-mirrorer`'s storage via human-friendly URLs (e.g. `git://gmr.lan/github.com/yuzu-emu/yuzu.git`)

## Wanted objects
If you run `git-mirrorer` with only a simple repos list, you might read the following log:
```
[WARN] Global wanted objects (when empty) not defined, adding 'HEAD' as default
[INFO] Repo 'https://github.com/yuzu-emu/yuzu' does not have wanted objects defined, adding global wanted objects (when empty) to it as wanted
```
A wanted object is what you can define for repos that can be parsed into commits that should be **robust** . They can either be defined for a repo, or globally.

A list of wanted object for repo can be defined like this:
```
repos:
  - https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git:
      wanted:
        - v6.4.10
        - v6.4.9
```

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

## Exporting
For every wanted object, you can export it as either `archive` or `checkout`, in both case they will contain all recursively submodules:
```
archive:
  pipe_through: zstd -22 --ultra
  suffix: .tar.zst
wanted:
  always:
    - all_branches:
        archive: yes
        checkout: yes
    - all_tags:
        archive: yes
        checkout: yes
repos:
  - https://github.com/yuzu-emu/yuzu
```
After a run with the above config, you will have a tree structure like the following:
```

archives/
├── data
│   ├── 42f4c8f28b8763631d5989543de99def528a93fc.tar.zst
│   └── db37e583ffea39a4d25a8eb3eeea0cf825ec6661.tar.zst
└── links
    ├── github.com
    │   └── yuzu-emu
    │       └── yuzu
    │           ├── 42f4c8f28b8763631d5989543de99def528a93fc.tar.zst -> ../../../../data/42f4c8f28b8763631d5989543de99def528a93fc.tar.zst
    │           ├── branches -> refs/heads
    │           ├── db37e583ffea39a4d25a8eb3eeea0cf825ec6661.tar.zst -> ../../../../data/db37e583ffea39a4d25a8eb3eeea0cf825ec6661.tar.zst
    │           └── refs
    │               └── heads
    │                   ├── master.tar.zst -> ../../../../../../data/db37e583ffea39a4d25a8eb3eeea0cf825ec6661.tar.zst
    │                   └── revert-11534-IFREMOVED.tar.zst -> ../../../../../../data/42f4c8f28b8763631d5989543de99def528a93fc.tar.zst
    └── gmr.lan
        └── github.com
            └── yuzu-emu
                └── yuzu
                    ├── 42f4c8f28b8763631d5989543de99def528a93fc.tar.zst -> ../../../../../data/42f4c8f28b8763631d5989543de99def528a93fc.tar.zst
                    ├── branches -> refs/heads
                    ├── db37e583ffea39a4d25a8eb3eeea0cf825ec6661.tar.zst -> ../../../../../data/db37e583ffea39a4d25a8eb3eeea0cf825ec6661.tar.zst
                    └── refs
                        └── heads
                            ├── master.tar.zst -> ../../../../../../../data/db37e583ffea39a4d25a8eb3eeea0cf825ec6661.tar.zst
                            └── revert-11534-IFREMOVED.tar.zst -> ../../../../../../../data/42f4c8f28b8763631d5989543de99def528a93fc.tar.zst
```
The file `archives/data/db37e583ffea39a4d25a8eb3eeea0cf825ec6661.tar.zst` would contain all of the content existing at `yuzu.git`'s that commit, **including submodules**;

Likewise, the folder `checkouts/data/db37e583ffea39a4d25a8eb3eeea0cf825ec6661` would also contain all of the content existing at `yuzu.git`'s that commit, **including submodules**. 

In both cases the submodules are stored as if they're plain folders in the parent git tree, e.g.
```
> ls checkouts/links/github.com/yuzu-emu/yuzu/branches/master/externals/cubeb/cmake/sanitizers-cmake/
cmake/  CMakeLists.txt  LICENSE  README.md  tests/
```
You can see that the submodule `externals/cubeb` 's submodule `cmake/sanitizers-cmake` exists with all of its content under the super project as `externals/cubeb/cmake/sanitizers-cmake`, which also applies to archives.

Do note that the `checkout`s here are really just `checkout`s, they're not `clone`s as there's no existing `.git` folder or file under the tree.

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
#### ~~`github_like_prefix`~~ (removed after v0.2)
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


## Cleaning
As `git-mirrorer` ensures the **robustness** of the wanted objects it fetches all of the repos that're referenced either directly or indirectly in the commits resolved from those wanted objects, **for every run**. Your `repos` folder might become larger and larger as you run `git-mirrorer` again and again to keep the repos up-to-date. The same applies to `archives` and `checkouts` if the wanted objects are dynamic and they point to new commits as you update the repos. 

By default `git-mirrorer` does not clean those folders but only the dead symlinks under `[repos/archives/checkouts]/links`, but you can set the following config to change its behaviour:

```
cleanup:
  repos: yes
  archives: yes
  checkouts: yes
  links_pass: 0
```
After repos are mirrored and needed archives/checkouts are created, `git-mirrorer` will delete any entry that's not needed under the corresponding folder to release the space.

The links can be cleaned for multiple passes during one execution, in case a single one does not clean those newly broken ones caused by other links being cleaned. You should only need that to be 1 if you're not touching the links folder by yourself.

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

## Advanced usage: as a daemon
Create a dedicated user for the job:
```
sudo useradd -d /srv/gmr -m -s /usr/bin/nologin gmr
```
Install the following systemd.service unit as `/etc/systemd/system/git-mirrorer.service`:
```
[Unit]
Description=git mirroring
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gmr
WorkingDirectory=/srv/gmr
ExecStart=/usr/bin/git-mirrorer --config config.yaml

[Install]
WantedBy=multi-user.target
```
Install the following systemd.timer unit as `/etc/systemd/system/git-mirrorer.timer`:
```
[Unit]
Description=Update mirrors per 10-minute

[Timer]
OnCalendar=*-*-* *:00,10,20,30,40,50:00

[Install]
WantedBy=timers.target
```
Configure the gmr instance:
```
sudo vi /srv/gmr/config.yaml
```
Enable the timer unit so it would update repos per 10-minute:
```
sudo systemctl enable --now git-mirrorer.timer
```
From now on, you can use it locally like following:
```
git clone /srv/gmr/repos/links/github.com/7Ji/git-mirrorer.git
```
However, you'll need to either by pass the ownership check of all these repos (`git config --global --add safe.directory '*'`) or change the service user to yourself, both of which would introduce safety concerns. For safety, it's recommended to follow the next step to set up a web service.

It should also be remembered that you should never push to such repo even if you can, as your commit would be replaced by remote commits as soon as git-mirrorer updates the local repo.

## Advanced usage: with nginx
Set up a locally serving daemon that updates the repo following the above steps.

Install both `nginx` and `fcgiwrap` and enable their units:

```
sudo pacman -Syu nginx fcgiwrap
sudo systemctl enable --now nginx.servie fcgiwrap.socket
```

Disable safe directory checking for `http` user:
```
printf '[safe]\n\tdirectory= *\n' | sudo install --owner http --group http --mode 644 /dev/stdin /srv/http/.gitconfig
```

Add the following nginx server config, with `server_name` switched out if you need:
```
server {
    listen       80;
    listen       [::]:80;
    server_name  gmr.lan;
    access_log   /var/log/nginx/gmr.lan.access.log;

    location ~ (/.*) {
        fastcgi_pass  unix:/run/fcgiwrap.sock;
        include       fastcgi_params;
        fastcgi_param SCRIPT_FILENAME     /usr/lib/git-core/git-http-backend;
        fastcgi_param GIT_HTTP_EXPORT_ALL "";
        fastcgi_param GIT_PROJECT_ROOT    /srv/gmr/repos/links;
        fastcgi_param PATH_INFO           $1;
        fastcgi_read_timeout            3600;
    }
    client_max_body_size 50m;
}
```
Reload `nginx` config:
```
sudo systemctl reload nginx.service
```

You should now be able to use it in the local web or global Internal like following:
```
git clone http://gmr.lan/github.com/7Ji/git-mirrorer.git
```
Note, altough it's possible to configure `git-http-backend` to allow pushing, it's not configured to do so here. As even if you can push, your commit would be replaced by remote commits as soon as git-mirrorer updates the local repo.

## Advanced usage: oneshot with stdin input
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