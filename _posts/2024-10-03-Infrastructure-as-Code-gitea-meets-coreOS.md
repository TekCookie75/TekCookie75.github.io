---
layout: post
title: "Infrastructure as Code: Gitea meets Fedora CoreOS"
subtitle: Deploying your own gitea from code
tags: [Home Lab, DevOps]
# cover-img: /assets/img/path.jpg
# thumbnail-img: /assets/img/thumb.png
# share-img: /assets/img/path.jpg
# comments: true
# mathjax: true
author: TekCookie75
---

# Infrastructure as Code: Gitea meets Fedora CoreOS

## Abstract

*Infrastructure as code (IaC)* uses DevOps methodology and versioning with a descriptive model to define and deploy infrastructure. Just as the same source code always generates the same binary, an IaC model generates the same environment every time it deploys. 

In this blog post, we will use [Ignition](https://docs.fedoraproject.org/en-US/fedora-coreos/producing-ign/) to create a descriptive model of a Fedora Core OS infrastructure, including `podman` providing a basic `gitea` container. While developing the descriptive model, we will focus on the basic principles of *Infrastructure as code* only. Thus, we will not implement security best practices, like securing `gitea` behind a reverse proxy or implementing any advanced authentication mechanism. Anyways, in the end of this post, you will have a `git` repository hosting the entire infrastructure model by means of code. You will be enabled to extend your infrastructure model on your own to develop this proof of concept presented here into a fully productive `gitea` server for home lab use. Deployment and Re-deployment will be as simple as executing a few scripts, while the data will remain persistent over each re-creation.

For the sake of this blog post, we will have to install CoreOS several times, each time improving our descriptive model. To this end, it is recommend to install the operating system to any kind of virtualization environment. Even more, I would recommend to conduct the first few installations in a local development and testing environment to speed up the process. For the sake of this blog post I will use a local *Fedora Workstation* machine with `libvirt` / `virish` to manage virtual machines. Later, once the model is in a productive state, I will transit to Proxmox VE node. 

Note that this blog post will be quite long, since we will build up the infrastructure step by step. To better follow along with the post I split up the post into four main sections covering the following topics.

1. In this first part, we will elaborate on Ignition and how to deploy a minimal Fedora CoreOS infrastructure in a local development environment. If you are already familiar with CoreOS and/or the RHEL Linux family you may like to skip this section.
2. Part two will add up on this basic CoreOS instance and describe how to customize the infrastructure by setting common UNIX/Linux parameters like `hostname`, network settings, and related configurations. The entire goal of this section will be to make the base OS  more robust and production ready for the next steps.
3. In the third part, we will add  `podman`, related services and the actual `gitea` infrastructure; all in a descriptive way; such that we obtain a `gitea` instance completely described by means of basic `yaml` code.
4. Part four will be all about integration and migration to the actual production environment. For the sake if this blog post, I will show how to use the descriptive model to deploy it on a Proxmox VE node.

So feel free to jump around the sections as you need. :-)

So do not lose any time and let us directly dive into the basics of Fedora CoreOS and the descriptive power of Ignition. If you are interested in the final results only, feel free to skip this series entirely and directly refer to the [project](https://github.com/TekCookie75/IaC-gitea-poc) on my GitHub account. A short `Readme.md` on how to use the developed model is provided there, too.

-----
## Part 1: CoreOS Installation - From Ignition to Instance

Let us start very simple, and create our first instance of Fedora CoreOS. This machine will not yet be very useful itself, but will explain the basic steps to walk-through in order to deploy CoreOS from code. Also this section will discuss the required build tools.

However, before we can start with the actual description of our minimal infrastructure, we should download the Fedora CoreOS image from the official [page](https://fedoraproject.org/de/coreos/download?stream=stable&arch=x86_64#download_section) first. Make sure to use the correct architecture. For the sake of this post, we will use the bare-metal `x86_64` installer `iso` for the production environment later on; and the backing storage `*.qcow2` cloud image for the development instance now. So, I will will download the virtualized QEMU image for this section.

From the official [documentation](https://docs.fedoraproject.org/en-US/fedora-coreos/producing-ign/) we copy the minimal working example. Make sure to replace the `ssh_authorized_key` with the one you are currently using!

```yaml
variant: fcos
version: 1.5.0
passwd:
  users:
    - name: core
      ssh_authorized_keys:
        - ssh-rsa AAAA...
```

If you do not have the possibility to use SSH in your development environment for some reason, you can add a password to the `core` user as well, however for security reasons consider removing the password instance before transitioning to a productive environment.

By using a password you will be enabled to log into CoreOS from the console. Especially during development and testing this can be an advantage, however once again, make sure to later remove this section from your configuration when transitioning to production environment or replace it by a very secure password!

To generate a password hash we have to use `mkpassword` utility from the `whois` package. Since some distribution will ship with slightly different implementations of `mkpassword`, I would recommend to use `podman` or `docker` to generate the password by the following command:

```bash
podman run -ti --rm quay.io/coreos/mkpasswd --method=yescrypt
```

Another advantage of this approach is that it will likely run on Windows as well. Anyways, once we have generated the password hash, we can simply extend our configuration:

```yaml
variant: fcos
version: 1.5.0
passwd:
  users:
    - name: core
      # Plaintext password: core
      # REMOVE THIS LINE IN PRODUCTION ENVIRONMENT (or replace by secure password at least!)
      password_hash: $y$j9T$UQQ5Ku9IGuoKKsus1FQu/0$ff/nk2KFw5U5KuNxH.nzmMZFFt7LaagWxHr/gUVxUU6
      ssh_authorized_keys:
        - ssh-rsa AAAA...
```

We have our first descriptive model of a CoreOS instance having a user named `core` assigned with a public SSH key for authentication. For more details on users and authentication refer to the official documentation ([link](https://docs.fedoraproject.org/en-US/fedora-coreos/authentication/)).

In order to use the configuration, it needs to be converted to more machine readable format. This can be done by using `butane`. Depending on your operating system, several possibilities of installation exist. For a more detailed instructions please refer to the official [documentation](https://docs.fedoraproject.org/en-US/fedora-coreos/producing-ign/). Since I am working on a *Fedora Workstation*, I am in the lucky situation of simply installing `butane` by

```bash
sudo dnf install -y butane
```

Alternatively, it can be ran inside a `docker` / `podman` container to be more independent of the actual operating system used.

```bash
podman run \
	--interactive \
	--rm \
	--security-opt label=disable \
    --volume ${PWD}:/pwd \
    --workdir /pwd quay.io/coreos/butane:release \
    --pretty \
    --strict Fedora-CoreOS.yaml > Fedora-CoreOS.ign
```

If using the basic command-line utility, we have to execute

```bash
butane --pretty --strict Fedora-CoreOS.yaml > Fedora-CoreOS.ign
```

where `Fedora-CoreOS.yaml` is the `YAML` document holding the descriptive model of our infrastructure.

Now, the created `*.ign` file may be used for deployment. Since, we will go through these deployment several times, it is best practice to create some kind of testing environment. Thus, in the following I will use `virsh` to generate the machine locally. If you directly want to deploy the machine to your Proxmox VE, refer to the instructions presented in part 4 of this post.

For the sake of fast deployment I will use the following `deploy.sh` script. It starts by assigning the correct `selinux` label to the Ignition file created before. This step is only required if your system runs `selinux`. Next, we will use `virt-install` to create the VM itself. The most of the parameters should be self-explaining. Only, the `--qemu-commandline` and the `--disk` parameters may need more attention. For the command line, we simply specify our Ignition file. The disk is specified by `backing_store`, here, since for this installation, we will not use the `iso` installer, but relaying on the provided `qcow2` cloud images.

```bash
#! /bin/bash

# Setup the correct SELinux label to allow access to the config
chcon --verbose --type svirt_home_t ${PWD}/Fedora-CoreOS.ign

# Start a Fedora CoreOS virtual machine
virt-install \
	--connect="qemu:///system" \
	--name=fcos \
	--vcpus=2 \
	--ram=2048 \
	--os-variant=fedora-coreos-stable \
	--import --graphics=none \
	--qemu-commandline="-fw_cfg name=opt/com.coreos/config,file=${PWD}/Fedora-CoreOS.ign" \
	--disk=size=20,backing_store=${PWD}/iso/fedora-coreos.qcow2 \
```

Once, the `deploy.sh` script is executed, a new virtual machine should be available on your host. You can spot the IP address from the scripts output and connect to the VM using your SSH key and the `core` user. Alternatively, if a password was set up, you can directly log in using these credentials.

Congratulation, you have deployed your first machine from code. Re-deployment will be as easy as deleting the old VM and execute `deploy.sh` again; and the best: Each time you will have the exact same environment!

In the following sections of this blog post, we will build up on this basic `yaml` configuration and add more and more functionality to our system. 

----
## Part 2: A better CoreOS - Adding features and improving convenience

In the last section, we have introduced our minimal working descriptive model of our new infrastructure. Theoretically, from here on, we could install `podman`, `gitea` and setup all the required services and files we like by hand. However, there is a better alternative: Describing the desired state in the Ignition file! 

But before improving the model, remember how close *Infrastructure as Code* is linked with versioning. Hence, now is the perfect time to enable version tracking for our descriptive model we will build up in the next sections. Thus, create a new directory. For the sake of this lab I will simply name it `TekCookie-gitea`. Inside this directory, we will initialize a new git repository.

```bash
git init /home/TekCookie75/Projects/TekCookie-gitea
```

Next, copy our initial `Fedora-CoreOS.yaml` and the `deploy.sh` script from part one to the newly created repository. To have the same naming scheme, let us also create the directories `config`, `service`, `iso` and `podman`. For the `podman` directory we create children named `containers`, `environment`, `networks` and `volumes`. The later will be used in part three to describe the actual container infrastructure. Inside the `iso` folder we can already place the downloaded `qcow2` cloud deployment image. 

```
.
├── config
├── deploy.sh
├── Fedora-CoreOS.yml
├── iso
    ├── fedora-coreos-x86_x64.iso
│   └── fedora-coreos.qcow2
├── podman
│   ├── containers
│   ├── environment
│   ├── networks
│   └── volumes
├── Readme.md
└── service
```

**Disclaimer:**
*For this blog post I copied the Fedora CoreOS images inside the repository for convenience reasons. However it is not a good idea to apply version tracking to big binary files like the `qcow2` image or `iso`. So, if you decide to apply the same structure make sure to either use git [LFS](https://git-lfs.com/) or excluding these files from your repository by using a `.gitignore` file.*

Once, the directory structure is created and a nice little `README.md` file may be created as well, we may like to make our first initial commit to the repository.

```bash
git add .
git commit -m ":tada: Initial commit"
```

Now, versioning is enabled on our infrastructure model and we can finally start to extend our minimal CoreOS instance from the previous section by adding more and more descriptive content to the `Fedora-CoreOS.yaml`. Notice, that all the configuration is available in the final model published on my coresponding GitHub [project](https://github.com/TekCookie75/IaC-gitea-poc).

The first thing we may like to do is setting a custom network configuration. We create a new file called `network.conf` and place it inside the `config` directory. The basic network setup follows the principles and syntax of `netplan`. So if you are unfamiliar with this, a lot of good resources will be available on the internet. Below is my config used in my local lab environment. Your configuration may differ depending on how your local setup and *virtual bridge* device is configured in your environment.

**Notice** *Your network interface name may be different depending on hardware or virtualization platform. Here I assume `enp6s18`.*

```ini
[connection]
id=enp6s18
type=ethernet
interface-name=enp6s18

[ipv4]
dhcp4=true
dhcp6=false
dhcp-hostname=gitea
dns=172.16.50.1
dns-search=lab.zz
may-fail=false
method=manual
```

To apply this configuration within our Ignition process, we have to add it to the `Fedora-CoreOS.yaml` by adding a `storage.files` entry. The updated configuration file is provided below.

```yaml
variant: fcos
version: 1.5.0
storage:
  files:
    - path: /etc/NetworkManager/system-connections/enp6s18.nmconnection
      mode: 0600
      contents:
        local: config/network.conf
passwd:
  users:
    - name: core
      ssh_authorized_keys:
        - ssh-rsa AAAA...
```

Next, let us set a custom hostname, e.g., `gitea`, and disable `systemd` pager when printing messages. To this end, we extend the `files` section by two additional entries.

```yaml
variant: fcos
version: 1.5.0
storage:
  files:
    - path: /etc/NetworkManager/system-connections/enp1s0.nmconnection
      mode: 0600
      contents:
        local: config/network.conf
    - path: /etc/hostname
      mode: 0644
      contents:
        inline: |
          gitea
    - path: /etc/profile.d/systemd-pager.sh
      mode: 0644
      contents:
        inline: |
          export SYSTEMD_PAGER=cat
passwd:
  users:
    - name: core
      ssh_authorized_keys:
        - ssh-rsa AAAA...
```

One of the main disadvantages we immediately spot is the increasing of complexity of our model. Especially considering larger configuration files may be bloating up our `yaml` file. So let us take the benefits of modularization and try to put us much of our settings into separate files in the `config` directory, like we did with `network.conf`; and only referencing them in the `Fedora-CoreOS.yaml`.

With this in mind, let us create a basic configuration files for `journald`, i.e., `journald.conf` with the contents

```ini
[Journal]
SystemMaxUse=200M
SystemMaxFileSize=20M
```

as well as an `audit.conf` having the contents

```ini
# Raise console message logging level from DEBUG (7) to WARNING (4)
# to hide audit messages from the interactive console
kernel.printk=4
```

The last setting will simply decrease the log level such that no longer disturbing `DEBUG` messages will be spammed around and filling up our logs and screen space. :-)

Finally, we may like to enable automatic updates. Fedora CoreOS provides scheduled updates by the `zincati` service. For the sake of this blog post, I will use the following update strategy, placed in `config/update-strategy.toml`.

```toml
[updates]
strategy="periodic"

[[updates.periodic.window]]
days=[ "Mon", "Wed","Fri", "Sun" ]
start_time="22:30"
length_minutes=60
```

After having created all of these configuration files, your project directory should look like the following and we only need to include the files in our central `yaml` file. 

```bash
.
├── config
│   ├── audit.conf
│   ├── hostname.conf
│   ├── journald.conf
│   ├── network.conf
│   ├── systemd-pager.sh
│   └── update-strategy.toml
├── Fedora-CoreOS.yml
```

Notice, that in the example depiction below I also put `hostname` and `systemd-pager.sh` configuration files to the external `config` directory to stay consistent in our syntax. You should be easily able to make these modifications on your own.

The updated `Fedora-CoreOS.yaml` is shown below. Compared to the previous version, here we only reference the configuration files created above. Also I added a new user named `git`, in which context the later `gitea` instance will run. Note that it is best practice to maintain the principle of least privilege. Hence running any exposed software like our `gitea` within the scope of `core` user is not a good idea, since `core` is allowed to use `sudo` without credentials by default! Also notice that I assigned each of the users a **weak password**. This is done for our convenience in the testing phase only and **should be removed in production later on!**

```yaml
variant: fcos
version: 1.5.0

storage:
  files:
   - path: /etc/hostname
     mode: 0644
     contents:
       local: config/hostname.conf
       
   - path: /etc/profile.d/systemd-pager.sh
     mode: 0644
     contents:
       local: config/systemd-pager.sh
       
   - path: /etc/sysctl.d/20-silence-audit.conf
     mode: 0644
     contents:
       local: config/audit.conf       

   - path: /etc/systemd/journald.conf
     mode: 0644
     overwrite: true
     contents:
       local: config/journald.conf

   - path: /etc/zincati/config.d/55-updates-strategy.toml
   - mode: 0644
     contents:
       local: config/update-strategy.toml

   - path: /etc/NetworkManager/system-connections/enp1s0.nmconnection
     mode: 0644
     contents:
       local: config/network.conf

passwd:
  users:
    - name: core
      # Plaintext password: core
      password_hash: $y$j9T$UQQ5Ku9IGuoKKsus1FQu/0$ff/nk2KFw5U5KuNxH.nzmMZFFt7LaagWxHr/gUVxUU6
      ssh_authorized_keys:
        - ssh-ed25519 <YOUR_SSH_KEY_HERE>
     - name: git
       # Plaintext password: git
       password_hash: $y$j9T$rEkShZWhHgVKp61PKVjd6.$IKKUpKst4LJDxVSWEUHGxNEKF8Gr5sq4TgXQKgZkBm7
       ssh_authorized_keys: <YOUR_SSH_KEY_HERE>
```

As a little bonus, if you are running CoreOS on `qemu` based virtualization environment like Proxmox, or using `libvirt`, you may like to overlay the `qemu-guest-agent` during installation. To this end, create a new service file named `rpm-ostree-install-qemu-guest-agent.service` inside the `service` directory.

```
[Unit]
Description=Layer qemu-guest-agent with rpm-ostree
Wants=network-online.target
After=network-online.target
# We run before `zincati.service` to avoid conflicting rpm-ostree
# transactions.
Before=zincati.service
ConditionPathExists=!/var/lib/%N.stamp

[Service]
Type=oneshot
RemainAfterExit=yes

# `--allow-inactive` ensures that rpm-ostree does not return an error
# if the package is already installed. This is useful if the package is
# added to the root image in a future Fedora CoreOS release as it will
# prevent the service from failing.
ExecStart=/usr/bin/rpm-ostree install --apply-live --allow-inactive qemu-guest-agent
ExecStart=/bin/touch /var/lib/%N.stamp

[Install]
WantedBy=multi-user.target
```

Finally, add it to the Ignition `Fedora-CoreOS.yaml` by adding a `systemd` section right after the `version` tag and before the `storage` section. 

```yaml
variant: fcos
version: 1.5.0

systemd:
  units:
   - name: rpm-ostree-install.qemu-guest-agent.service
     enabled: true
     contents_local: service/rpm-ostree-install-qemu-guest-agent.service

storage:
  files:
    # ...
```

For your reference, the complete files can be found in the projects GitHub [repository](https://github.com/TekCookie75/IaC-gitea-poc).

Now re-create the VM using the `deploy.sh` script, and enjoy your improved version of CoreOS including automatic updates, custom static network configuration and hostname setting. Again the powerful part on this approach is the descriptive nature of our infrastructure. We can destroy and re-create the VM over and over again, each time obtaining the exact same machine!

In the next part of this blog post, we will extend on, and will describe the actual `gitea` and related database services. 

----

## Part 3: CoreOS loves Containerization

The entire Fedora CoreOS distribution is build around containerization. Hence, no wonder that technology stacks like `docker`, `compose` and `podman` are part of the distribution. For this blog post I like to use `podman`. One of the very helpful options with `podman` is that it allows us to define container structure by means of `systemd` unit like entities. This will be perfect to describe the container infrastructure by  simple`systemd` unit files and embed them into our infrastructure model from part two of these series.

**Disclaimer**
The following section will assume that you are already comfortable with `podman` or `docker` syntax, since an introduction to the later is simply out of the scope of this blog post. For a translation from `podman` / `docker` command-line to the `systemd` unit style files, we refer to the official `podman` [documentation](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html).

Anyways, before adding `gitea` and related containers to our model, let us first check, what `gitea` is expecting from us. Considering the [official documentation](https://docs.gitea.com/installation/install-with-docker-rootless) the following file is provided to deploy `gitea` using `docker compose`.

```yaml
version: "2"

volumes:
  gitea-data:
    driver: local
  gitea-config:
    driver: local+

services:
  server:
    image: gitea/gitea:1.22.2-rootless
     environment:
       - GITEA__database__DB_TYPE=mysql
       - GITEA__database__HOST=db:3306
       - GITEA__database__NAME=gitea
       - GITEA__database__USER=gitea
       - GITEA__database__PASSWD=gitea
    restart: always
    volumes:
      - gitea-data:/var/lib/gitea:/var/lib/gitea
      - gitea-config:/etc/gitea
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
    ports:
      - "3000:3000"
      - "2222:2222"
     depends_on:
       - db
 
   db:
     image: mysql:8
     restart: always
     environment:
       - MYSQL_ROOT_PASSWORD=gitea
       - MYSQL_USER=gitea
       - MYSQL_PASSWORD=gitea
       - MYSQL_DATABASE=gitea
     volumes:
       - ./mysql:/var/lib/mysql
```

Inspecting this `yaml` file, we spot two containers, namely the actual `gitea` one and a database container, here `mysql`. Also, we have two named volumes, i.e., `gitea-data` and `gitea-config` holding user- and configuration data for `gitea`; as well as several environmental parameters like database credentials.

Considering the goal of infrastructure as code, our ultimate goal will be to split up this large`compose` file into several easily maintainable modules and embed these into our descriptive model. Also, we will have to make minor syntactical transitions due to the usage of `podman` instead of `docker`. However, the benefits will be worth the pain once the model is defined!

Now, let us begin by creating a basic `podman` `network` used for the internal communication between the `gitea` container and the database container. While this step is optional, it will provide us with network segmentation and isolation in the first place. Thus, when later extending our infrastructure by another service, we can separate it to different network. The syntax will be very simple, the only requirement is that the file does have `*.network` extension. In our repository we create a new file named `gitea-net.network` inside the `podman/networks` directory.

```ini
[Network]
DisableDNS=false
Internal=true
Subnet=192.168.30.0/24
Gateway=192.168.30.1
```

Make sure to have `DNS` enabled by setting `DisableDNS=false`, otherwise communication between the containers may be disturbed later on. Also, we set the network to `internal` only. The settings on Subnet and Gateway can be adopted to any private network specification.

Next, after having defined the basis for communication, let us care about the data persistence by defining the required named `volumes`.

Creation of `volumes` is very straight forward. To later run `gitea`, we required the three volumes as already observed in the official `compose` file provided by `gitea`. To repeat on them, I will use the following volumes with corresponding names:
- `mariadb.volume` - Holding the persistent data of the database backend.
- `gitea-config.volume` - Volume used to store the configuration of `gitea`
- `gitea-data.volume` - Persistent storage used for the repositories and user data

For the sake of our initial proof of concept, we need to specify the `Unit` and `Volume` tags only. For all the available parameters check out the [volume documentation](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) of `podman`.


```
[Unit]
Description=Maria DB Volume
    
[Volume]
```


```
[Unit]
Description=Gitea Configuration Files - Volume
      
[Volume]
```


```
[Unit]
Description=Gitea Application Data Files - Volume
      
[Volume]
```


Finally, we need two containers. One for the database, here we use a `mariadb` container; and second, the actual `gitea` container.

Below is the `mariadb.container` file from the `podman/containers` directory.

```
[Unit]
Description=MariaDB Container

Wants=network.target
After=network-online.target
RequiresMountsFor=%t/containers


[Container]
Image=docker.io/library/mariadb
ContainerName=gitea-db
AutoUpdate=registry
EnvironmentFile=/home/git/.config/containers/gitea.env
Volume=mariadb.volume:/var/lib/mysql:Z
Network=gitea-net.network

[Service]
Restart=on-failure
TimeoutStartSec=900
TimeoutStopSec=70


[Install]
RequiredBy=gitea.service
WantedBy=multi-user.target default.target
```

Looking at this service file there should be not really surprises if you were familiar with `systemd` and `podman` / `docker`. After description of the unit files purpose, we define basic dependencies of the unit. So, the unit should not start before the mount points for the container data are available, or the network connection is established. Afterwards, in the `[container]` section, we specify the image to use, the container name, the volumes to mount and network to host this container on. Also notice the setting on `EnvironmentFile`, on which I will elaborate in more detail later on! The service unit ends with prescription of a restart policy and by defining the dependency to the `gitea.service`, which we will define by the next unit file.

```
[Unit]
Description=Gitea Container

Wants=network.target
After=network-online.target
RequiresMountsFor=%t/containers


[Container]
Image=docker.io/gitea/gitea:1-rootless
ContainerName=gitea
AutoUpdate=registry
EnvironmentFile=/home/core/.config/containers/gitea.env
Volume=gitea-data.volume:/var/lib/gitea:Z
Volume=gitea-config.volume:/etc/gitea:Z
Network=gitea-net.network
PublishPort=2222:2222
PublishPort=3000:3000

[Service]
Restart=on-failure
TimeoutStartSec=900
TimeoutStopSec=70


[Install]
WantedBy=multi-user.target default.target
```

The structure is nearly identically with the one for `mariadb.container`. Anyways, let us focus on some new aspects of `podman/containers/gitea.container` unit file. Here, the `PublishPort` parameter is used to make the internal ports `2222` (*SSH*) and `3000` (*Web*) from the `gitea-net.network` available to the outside, i.e., to our host. So, we will be able to access these ports from external.

To sum up, compare and note the similarities to the initial discussed `compose.yaml` file from `gitea`. Also notice how much more clean these files will look. Also, all the environmental parameters were separated to an external file named `container-enviornment` for maintainability.

*Here, I used one environment file for both containers, since they are somehow inextricably linked. However, splitting them up into one environment per container would be possible.*

```ini
# Environmental parameters for the mariadb container
#
MARIADB_RANDOM_ROOT_PASSWORD=yes
MARIADB_DATABASE=gitea
MARIADB_USER=gitea
MARIADB_PASSWORD=<STRONG_PASSWORD_HERE>


# Environmental parameters for the gitea instance
#
DB_TYPE=mysql
DB_HOST=gitea-db:3306
DB_NAME=gitea
DB_USER=gitea
DB_PASSWD=<STRONG_PASSWORD_HERE>
```

After creating each of these files, our working repository should look roughly similar to the following structure

```bash
├── podman
│   ├── containers
│   │   ├── gitea.container
│   │   └── mariadb.container
│   ├── environment
│   │   └── gitea.env
│   ├── networks
│   │   └── gitea-net.network
│   └── volumes
│       ├── gitea-config.volume
│       ├── gitea-data.volume
│       └── mariadb.volume
```

To make use of these service files, we have to add them to our Ignition file. However, this is as simple as adding the following lines to our `Fedora-CoreOS.yaml`.

```yaml
storage:
  files:
   - path: /home/git/.config/containers/containers-environment
     mode: 0600
     contents:
       local: podman/environment/gitea.env
     user:
       name: git
     group:
       name: git
   - path: /home/git/.config/containers/systemd/gitea-net.network
     contents:
       local: podman/networks/gitea-net.network
     user:
       name: git
     group:
       name: git
   - path: /home/git/.config/containers/systemd/mariadb.volume
     contents:
       local: podman/volumes/mariadb.volume
     user:
       name: git
     group:
       name: git
   - path: /home/git/.config/containers/systemd/gitea-data.volume
     contents:
       local: podman/volumes/gitea-data.volume
     user:
       name: git
     group:
       name: git
   - path: /home/git/.config/containers/systemd/gitea-config.volume
     contents:
       local: podman/volumes/gitea-config.volume
     user:
       name: git
     group:
       name: git
   - path: /home/git/.config/containers/systemd/mariadb.container
     contents:
       local: podman/containers/mariadb.container
     mode: 0600
     user:
       name: git
     group:
       name: git
   - path: /home/git/.config/containers/systemd/gitea.container
     contents:
       local: podman/containers/gitea.container
     mode: 0600
     user:
       name: git
     group:
       name: git
```

While the `yaml` file is not very conscious, the syntax is easy to understand and maintain. Anyways, if you would try to deploy the machine yet, you will likely run into an issue where all the created `systemd` like units will not start. The reason is *"kind of bug, but feature of CoreOS"* thing. CoreOS is not able to create all the unit files in `/home/git/.config/containers/systemd/` since this directory does not exist yet! Thus, we have to manually create it; and all the parents. Spoken in code, we have to add

```yaml
storage:
  directories:
    # setting up directory permissions required to avoid
    # failure when starting `podman`
    # due to bug (missing feature) in butane, we have to 
    # create each of the nested directories seperatly!
    - path: /home/git/.config
      user:
        name: git
      group:
        name: git
    - path: /home/git/.config/containers
      user:
        name: git
      group:
        name: git
    - path: /home/git/.config/containers/systemd
      user:
        name: git
      group:
        name: git
```

Unfortunately, this will add a lot of boiler code to our model. I hope that in future there will be a more easy way to create a directory and all it parent directories recursively in Ignition! If you know a way to improve this, pleas let me know in the comments. Thanks!

Another step will be to enable `lingering` on the `git` user. This will be required to start the `systemd` units of the containers at boot and persist them beyond user sessions. Otherwise, our `gitea` would only be available while we have an active session as the `git` user! Enable `systemd linger` from the console is only one simple command, i.e.,

```bash
sudo loginctl enable-linger <USER>
```

To achieve the same effect in our descriptive model, we have to make Ignition create an empty file under `/var/lib/systemd/linger` with the name `<USER>`.  Thus, we have to merge the following lines of code into our configuration:

```yaml
storage:
  files:
    # Create an empty /var/lib/systemd/linger/<USER> file
    # to enable linger for the <USER> account
    # Lingering is required to boot systemd user units at boot
    # Equal to: sudo loginctl enable-linger $USER
    - path: /var/lib/systemd/linger/git
      mode: 0644
```

Also at that time you may like to add and enable `podman-auto-update.timer` in your Ignition configuration. To this end, the following code snippets needs to be merged inside your `Fedora-CoreOS.yaml` configuration file.

```yaml
systemd:
  units:
   # Enable Podman auto-updater for container images
   - name: podman-auto-update.timer
     enabled: true
storage:
  links:
    # setting link to podman-auto-update.timer in order to run
    # it with low privileges
    - path: /home/git/.config/systemd/user/timers.target.wants/podman-auto-update.timer
      target: /usr/lib/systemd/user/podman-auto-update.timer
      user:
        name: git
      group:
        name: git
  directories:
    - path: /home/git/.config
      user:
        name: git
      group:
        name: git
    - path: /home/git/.config/systemd
      user:
        name: git
      group:
        name: git
    - path: /home/git/.config/systemd/user
      user:
        name: git
      group:
        name: git
    - path: /home/git/.config/systemd/user/timers.target.wants
      user:
        name: git
      group:
        name: git
```

Basically, this part will create the required directories to then create a soft-link of `/usr/lib/systemd/user/podman-auto-update.timer` to the local directories of `git` user in order to allow the service to be ran with low privileges. Finally, the service will be enabled. 
Anyways, I will not discuss this here in more detail. Adding this feature should be manageable by the reader. If you need some guidance on it, check out the final project state including the  complete project files in the projects repository on GitHub ([link](https://github.com/TekCookie75/IaC-gitea-poc)).

So to sum up the steps until here, we have a basic descriptive model of our infrastructure. Due to the nature of infrastructure as code, we can easily re-deploy our environment without losing any configurations. However, what we did not discussed yet is the persistence of user and/or application data. This is a whole different story and will be one of our main focuses in the next section. In that next and final step, we will migrate this development prototype to the production environment.

----

## Part 4: From Ignition to Production

In this last section, we will use the descriptive model of our infrastructure and host it on a Proxmox VE node. This discussion assumes that you already have an up to date Proxmox VE instance running. If you need any guidance on how to install and administrate Proxmox, please refer to one of the many good resources on this topic.

We start by creating a new virtual machine on our `Proxmox VE` host. The parameters may be left with the default one. For the sake of this post, we set the following hardware specifications to our VM.

- 2 vCPU
- 4096 MB of memory (2048 MB balloon size)
- 8 GB main disk size used for the installation of CoreOS; excluded from backup
- additional 64 GB disk for  container data (*persistent storage*)
- CD drive with mounted `iso` image of current Fedora CoreOS release `x86_64`

**Notice**, that for the production environment, we will use two disks to separate the actual user data from the "infrastructure data" generated by our code. This will allow us to re-deploy the environment without losing any data. Also for the sake of performance, we excluded the OS disk from backup. There is no need to backup anything here, since we can easily recover the entire infrastructure by using our descriptive model.

If you also decide to use a second disk like me, which is the recommended way (!), do not forget to set it up in the descriptive model. To this end, the following changes are required to the `Fedora-CoreOS.yaml`.

```yaml
storage:
  disks:
    - device: /dev/sdb
      wipe_table: false
      partitions:
        - size_mib: 0
          start_mib: 0
          label: podman-volumes
  filesystems:
    - path: /var/home/git/.local/share/containers/volumes
      device: /dev/disk/by-partlabel/podman-volumes
      wipe_filesystem: false
      format: xfs
      with_mount_unit: true
      mount_options:
        - noatime
```

Notice, if you have any issue with putting the puzzles together, the complete configuration file is available on my GitHub [project](https://github.com/TekCookie75/IaC-gitea-poc) page!

Once the VM is create, we can start it. In the boot loader we select to start `Fedora CoreOS Live` mode. After the system has booted, we download the Ignitation script created on our local machine. To this end, we can easily request the Ignition file from our bastion host by e.g., using `curl`. I.e.,

```bash
curl -O http://local-bastion-host:8080/Fedora-CoreOS.ign
```

Once, the script is locally available on the VM, we can deploy the `CoreOS` instance by one simple command.

```bash
sudo coreos-installer install /dev/sda --ignition-file ./Fedora-CoreOS.ign
```

The installation succeeds after short amount of time and we can shut it down.

```bash
sudo poweroff
```

Now, make sure to remove the virtual installation disk, before powering on the machine again. If everything well, `systemd` will install the `qemu-guest-agent` and all the `podman` containers, volumes and networks we have specified in our model. This may take some time depending on your network speed. Anyways, after round about 3 to 5 Minutes, you should be able to browse https://core-os-ip:3000 and see you private `gitea` instance. Since we do not have specified an administrator account in our model, an administrative account have to be created on the first access of the first deployment. Any following deployment will have these settings already on the persisted configuration volumes.


## Part 5: Debugging the Issues

Hopefully your instance is running well and you do not need to read through this section at all. Anyways, developing means producing bugs. So mistakes are natural. This section tries to give you some ideas where to look next, if anything goes wrong.

The most typical scenario is that you are able to deploy the model but `gitea` is not starting as intended. In sich case, start by checking 

```bash
podman ps
```

once logged in as the `git` user via SSH. You should see your running containers! If the output is still empty after 5-10 Minutes, it gets time to check `systemd`. Thanks to our deployment strategy, this is as easy as typing, e.g.,

```bash
systemctl --user status gitea.service
```

From the output you will usually get to know why `gitea` decided to not work like you want. :-)

For more detailed logs, refer to

```bash
journalctl --user -u gitea.service
```

If none of these logs will provide you with sufficient information, then from my experience it is always a permission error! Thus, it is a good idea to check the permissions on the named volumes. Sometimes `gitea` will not change the ownership correctly. So, check

```bash
ls -lisa /var/home/git/.local/share/containers/storage/volumes/systemd-gitea-config/_data
```

for any odd looking permissions and/or anomalies.

If all of these does not help, feel free to write in the comments and/or ask the community around. Best luck in fixing your issue. :-)

----

## Summary and Lessons Learned

That's it for this long post. I hope you have understood the basic principles of infrastructure as code and learned how you can apply it to your home lab environment. The best here is, that you now can easily extend your infrastructure by hosting more containers. Simply add the corresponding objects inside the `podman` directory of the repository and announce them inside the central `Fedora-CoreOS.yaml`.

Even if this blog post ended here, there is a lot of space for improvements. To name just a few ideas:

- This proof of concept project exposes `gitea` on ports 2222 and 3000 without implementing TLS veryfication. A next natural step will be to secure the `gitea` instance behind a reverse proxy implementing `HTTPS` and some form of secret management.
- In the current version, `git` contains the `environment` file containing plain-text credentials for the database. If you decide to host your model on a public place, you should definitively improve on this!
- To make the project scale better we may install an container orchestration like `portainer`, and then manage the `gitea` stack inside `portainer`.
- Using Ignition / Butane merge feature, the code can even be more modularization and refactored to your specific needs. Automation and pipeline development may be a good extend to this project!

So you see, there is a lot we can continue on to have a more secure and robust infrastructure. Consider the current projects state as starting point only! Personally, I will not continuing on any improvement. Instead I plan to come back to you with another blog post elaborating on my Kubernetes setup based on TalOS, which I am currently using in my Home Lab. So stay tuned for the next adventure. :-) 

And never forget, security and robustness are processes not terminating products. So with these words in mind have a wonderful day and enjoy hacking.

Thank you for reading!

-----
-----
