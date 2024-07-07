# git-mirrorer
To **mirror** git repos, and **archive** and **checkout** them with submodules included implicitly.

# Usage
## Basic
To let `git-mirrorer` mirror a list of repos, simply define them in a `.yaml` config file, and then pass the file to it via `--config [file]`, or feed the config into its stdin.

You can start from a simple config file like the following:
```
repos:
  - https://github.com/protocolbuffers/protobuf
```
After `./git-mirrorer --config config.yaml`, you will have the following directory structure:
```
repos
├── data
│   ├── 0744d8eaf6ede48e
│   │   ├── config
│   │   ├── description
│   │   ├── FETCH_HEAD
│   │   ├── HEAD
│   │   ├── hooks
│   │   │   └── README.sample
│   │   ├── info
│   │   │   └── exclude
│   │   ├── objects
│   │   │   ├── info
│   │   │   └── pack
│   │   │       ├── pack-7779f5aac69e69c3c1422fcc1394e5ead56f4b17.idx
│   │   │       └── pack-7779f5aac69e69c3c1422fcc1394e5ead56f4b17.pack
│   │   └── refs
│   │       ├── heads
│   │       │   ├── 00.11.z
│   │       │   └── ...
│   │       ├── pull
│   │       │   ├── 1
│   │       │   │   └── head
│   │       │   └── ...
│   │       └── tags
│   │           ├── 00.11.0
│   │           └── ...
│   ├── 23b62ae1298275e0/
│   ├── 64796b2d763671d0/
│   └── 67f763e658bca3c7/
└── links
    └── github.com
        ├── abseil
        │   └── abseil-cpp.git -> ../../../data/64796b2d763671d0
        ├── google
        │   └── googletest.git -> ../../../data/67f763e658bca3c7
        ├── open-source-parsers
        │   └── jsoncpp.git -> ../../../data/0744d8eaf6ede48e
        └── protocolbuffers
            └── protobuf.git -> ../../../data/23b62ae1298275e0
```

The structure is populated with the following logic for any remote repo that needs to be mirrored:
 1. `git-mirrorer` would mirror it into `repos/data/[HASH]`, where the `[HASH]` is unique for any given URL. This automatically avoids the problem where multiple remote repos share the same name.
 2. `git-mirrorer` would mirror any other repos that are referenced in the defined repos as submodules, so a complete repo tree could be constructed using only own local repos. By default only the HEAD commit of your defined repos are parsed like this.
 3. `git-mirrorer` would create symlinks under `repos/links` with paths composed of their URL segments pointing to the actual repos, so you can easily clone from `git-mirrorer`'s storage via human-friendly URLs (e.g. `git://gmr.lan/github.com/protocolbuffers/protobuf.git`)

## Wanted objects
If you run `git-mirrorer` with only a simple repos list, you might read the following log:
```
[WARN] Global wanted objects (when empty) not defined, adding 'HEAD' as default
[INFO] Repo 'https://github.com/protocolbuffers/protobuf' does not have wanted objects defined, adding global wanted objects (when empty) to it as wanted
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
  - https://github.com/protocolbuffers/protobuf
```
After a run with the above config, you will have a tree structure like the following:
```
archives
├── data
│   ├── 0091250e2f1de84ddd40d65ee1529fd9cbb7b2ec.tar.zst
│   ├── 011c685e9457c1723cdeef7d01cf06775edc8eea.tar.zst
│   ├── ...
│   └── fee2e00ce29bbb8cf35cafdea820e56a7fc34bc8.tar.zst
└── links
    └── github.com
        └── protocolbuffers
            └── protobuf
                ├── 0091250e2f1de84ddd40d65ee1529fd9cbb7b2ec.tar.zst -> ../../../../data/0091250e2f1de84ddd40d65ee1529fd9cbb7b2ec.tar.zst
                ├── 011c685e9457c1723cdeef7d01cf06775edc8eea.tar.zst -> ../../../../data/011c685e9457c1723cdeef7d01cf06775edc8eea.tar.zst
                ├── ...
                ├── fee2e00ce29bbb8cf35cafdea820e56a7fc34bc8.tar.zst -> ../../../../data/fee2e00ce29bbb8cf35cafdea820e56a7fc34bc8.tar.zst
                ├── refs
                │   ├── heads
                │   │   ├── 21.x.tar.zst -> ../../../../../../data/2798a968c330de223b711e4fe504800280f333fb.tar.zst
                │   │   ├── 22.x-202303072154.tar.zst -> ../../../../../../data/9c02d4c0de5b32225716483332c892692b19a483.tar.zst
                │   │   ├── 22.x-202304122338.tar.zst -> ../../../../../../data/5bc5cd29c98f3229db23ca6ce449b887662ed50d.tar.zst
                │   │   ├── ...
                │   │   ├── deannagarcia-patch-9.tar.zst -> ../../../../../../data/9fc2b889eab2fb174eb3f9221b3cd845859a6ec7.tar.zst
                │   │   ├── dependabot
                │   │   │   ├── github_actions
                │   │   │   │   ├── actions
                │   │   │   │   │   ├── cache-4.0.2.tar.zst -> ../../../../../../../../../data/424dea87613e38e60f154a38bc83f0b910eca257.tar.zst
                │   │   │   │   │   └── checkout-4.1.7.tar.zst -> ../../../../../../../../../data/7e83a736cc4087fe2f11efb74d103ee558a2080d.tar.zst
                │   │   │   │   └── ilammy
                │   │   │   │       └── msvc-dev-cmd-1.13.0.tar.zst -> ../../../../../../../../../data/18a0a9d88fa380e165aa9095e44b65f46c97eb62.tar.zst
                │   │   │   └── pip
                │   │   │       └── python
                │   │   │           └── docs
                │   │   │               └── jinja2-3.1.4.tar.zst -> ../../../../../../../../../../data/4b86de33e6b8b16c0549df373e4fd9c9ec4f7f4b.tar.zst
                │   │   ├── disable-upload-artifacts-action.tar.zst -> ../../../../../../data/87c458388d10d15b7090bcce1b17491cf4f47fba.tar.zst
                │   │   ├── ...
                │   │   └── win2019-23.x.tar.zst -> ../../../../../../data/1be47896d437e23c6632d8b7969ed4bebd3d7831.tar.zst
                │   └── tags
                │       ├── 3.15.0-rc1.tar.zst -> ../../../../../../data/66e5185780129ea749e8ee8183586b4355c64db0.tar.zst
                │       ├── conformance-build-tag.tar.zst -> ../../../../../../data/6dec8cf96e32fd7fb0121a75ca72acf10863ecc9.tar.zst
                │       ├── v16.2.tar.zst -> ../../../../../../data/c18f5e71d86063fd6cea2c47cd7ab4131db5c9e2.tar.zst
                │       ├── ...
                │       └── v5.27.2.tar.zst -> ../../../../../../data/63def39e881afa496502d9c410f4ea948e59490d.tar.zst
                └── tags -> refs/tags
checkouts/
```
The file `archives/data/03dac701f55bb08f622f9ee6f0a3cfe882caba65.tar.zst` would contain all of the content existing at `protobuf.git`'s that commit, **including submodules**;

Likewise, the folder `checkouts/data/03dac701f55bb08f622f9ee6f0a3cfe882caba65` would also contain all of the content existing at `protobuf.git`'s that commit, **including submodules**. 

In both cases the submodules are stored as if they're plain folders in the parent git tree

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
By default this is set to `no` and every entry is directly in the archive's root, e.g. `README.md` in that `protobuf.git` archive is stored as `README.md` in the archive. If set to `yes` then it is stored as `protobuf-03dac701f55bb08f622f9ee6f0a3cfe882caba65/README.md`.  
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