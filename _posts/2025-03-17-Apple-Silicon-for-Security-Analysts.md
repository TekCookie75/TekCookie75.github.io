---
layout: post
title: Is Apple Silicon a Smart Choice for Security Analysts?
subtitle: My opinion on Performance, compatibility, and real-world security workflows
tags: [Reverse Engineering, DFIR, Malware Analysis, Apple, Apple Silion]
# cover-img: https://tekcookie75.github.io/assets/img/posts/2024-12-15/path.jpg
# thumbnail-img: https://tekcookie75.github.io/assets/img/posts/2024-12-15/thumb.png
# share-img: https://tekcookie75.github.io/assets/img/posts/2024-12-15/path.jpg
# comments: true
# mathjax: true
author: TekCookie75
---

During my study times I observed that many of the professors, especially from the computer science departments, were using Apple devices. At that time the majority of Apple devices were powered by Intel processors. Since then a lot changed and nowadays all Apple devices were produces with Apple Silicon chips only. The ARM architecture changed a lot. In synthetic benchmarks Apple was able to prove that their M series CPUs were very capable. The CPUs provided a lot more performance compared to the Intel series ones built in earlier generations of Apple devices. At the same time they were very low power consuming. So at first glance, Apple Silicon seems to be the first choice due to high performance, long battery endurance, well designed ecosystem and user experience, combined with a solid build quality of their devices.

However is Apple Silicon a Smart Choice for Security Analysts?

In this little blog post I want to share my thoughts and opinion about the usage of a MacBook Pro M series laptop for the day to day security analysts job. I will share how I use the device for software development, security research, and malware analysis. I will not just mention the burdens of Apple Silicon but also provide possible solutions and workarounds. May at the end of this post, we will be able to decide on our own, whether a MacBook is a perfect accompanionfor you or not.

I will first shortly elaborate on package management, continouing with software development, arriving at the most interessting part of handling security related tasks on the machine.


# Everything starts with package management

If you were used to use a Linux machine, the first thing you will miss on MacOS is a package manager. While this has nothing directly to do with the day to day tasks of a security analysts or researcher, package management is a often overlooked topic in my eyes. Without a proper package manager, you may either miss important security fixes or newly introduced features just because you were not aware of any update. For sure, manually checking on each usage is possibel but very inconvinient. It requires a dicipline often lost during daily worktime. So for me a package manager is the foundation of a good OS.

This said, MacOS completely lacks support of an official package manager. There are options like **Homebrew**, **MacPorts** and **nix-darwin**. At least to my opinion non of them mets the convenience and features of, e.g., `apt` or `dnf`. Anyways, I decided to go for `nix-darwin. It integrates well with the OS and allows a complete declerative description of the machines packages installed. In a single file, we can define, which packages from the Apple App Store, the Homebrew tree and the nix packages repository we want to install on our system.

For my setup I am using the configuration attached below. A complete post about how Nix works is out of the scope of this blog. Good resources exist at the official [GitHub repository](https://github.com/nix-darwin/nix-darwin), [Determinate Systems](https://docs.determinate.systems/guides/nix-darwin/) and the blog from [Davis Haupt](https://davi.sh/blog/2024/01/nix-darwin/).

```nix
{
  description = "Nix-darwin system profile to manage basic properties of the MacOS environment using declerative nix language";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    nix-darwin.url = "github:nix-darwin/nix-darwin/master";
    nix-darwin.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = inputs@{ self, nix-darwin, nixpkgs }:
  let
    configuration = { pkgs, ... }: {
      # Allow safe migration
      system.activationScripts.migrateEtc.enable = true;

      # Enable TouchID for sudo
      # security.pam.enableSudoTouchIdAuth = true;
      security.pam.services.sudo_local.touchIdAuth = true;

      # List packages installed in system profile. To search by name, run:
      # $ nix-env -qaP | grep wget
      environment.systemPackages =
        [ pkgs.neovim
	      pkgs.powershell
		  pkgs.openssh
		  pkgs.exiftool
		  pkgs.nmap
		  pkgs.netcat
		  pkgs.awscli2
		  pkgs.bat
		  pkgs.tree
        ];

      # Add support for Homebrew packages
      homebrew = {
          enable = false;
	  onActivation.cleanup = "uninstall";

	  taps = [];
	  brews = [];
	  casks = [];
	  masApps = {
	    # Applications from Mac App Store
	    # managed via `mas` and `homebrew`
	  };
      };

      # Necessary for using flakes on this system.
      nix.settings.experimental-features = "nix-command flakes";

      # Enable alternative shell support in nix-darwin.
      # programs.fish.enable = true;

      # Set Git commit hash for darwin-version.
      system.configurationRevision = self.rev or self.dirtyRev or null;

      # Used for backwards compatibility, 
      # please read the changelog before changing.
      # $ darwin-rebuild changelog
      system.stateVersion = 6;

      # The platform the configuration will be used on.
      nixpkgs.hostPlatform = "aarch64-darwin";
    };
  in
  {
    # Build darwin flake using:
    # $ darwin-rebuild build --flake .#MacBook-Pro
    darwinConfigurations."MacBook-Pro" = nix-darwin.lib.darwinSystem {
      modules = [ configuration ];
    };
  };
}
```

As you can see I enabled *TouchID* for `sudo` for the sake of convenience and installed several classic Linux tools like `neovim`, `powershell`, `openssh`, `exiftool`, `nmap`, `netcat`, `awscli`, `bat` and `tree`. 

One thing I like on Nix is how easy it is to get a *temporary package*. Assuming you need a specific library or tool just for the sake of an analysis. With Nix it is possible to install it into a temporary namespace and removing it just when we leave the shell. E.g., 

```bash
nix-shell -p nmap
```

starts a new shell with `nmap` installed. Once we exit the shell, `nmap` is gone away as well. Also Nix packages are soft isolated using namespaces. Still from security perspective this is no security boundary and you have to trust the Nix packages repository as well. Anyways for me `nix-darwin` is the closest option possible to a usable package management under MacOS. Thus I accepted the risks and devided to live with the downsides.


# Software / Tool Development

Software development is an important aspect for security research and analysis. Often we need to either implement our own tooling or adopt existing one at least. To this end, we require access to several programming languages like `go`, `rust`, `python` and `C/C++` to just name some of them. Luckily MacOs is used by a majority of software developers and thus nearly any programming language does provide support for MacOS and Apple Silicon. Good IDEs are available as well. Personally, I just use *Visual Studio Code*.

For the sake of this post I will not detail about how to install any of these languages on MacOS. I assume that every one with the skill to program should be able to install the interpreter or compiler as well. However there are may one thing you encounter and get stucked on. 

Assume you want to use a third party library / toolchain like [quiling](https://github.com/qilingframework/qiling), which provides a Python binding at a first glance. So installing it according to the documentation using `pip` should work in theory! - However there is a pitfall. Many python bindings make usage of pre-compiled binaries and often these binary files are compiled for `x86_64`. Quiling is no exception here. If we try to install it via `pip` it will simply fail just because we are using Apple Silicon. There are ways to manually install it, by re-compiling the dependencies, and make it run on M series CPUs, however to my opinion there is a better option called Docker.

Docker is able to run any architecture software containerized and even does support Apples virtualization and emulation framework. This means we get top performance and `x86_64` emulation. Even more, the executed code is executed inside a container and another layer of security is added as well. Beside this it is predictable and reproducable. The later is also the reason that it is used by many CI/CD pipelines on Git. So nearly any modern software can be fit inside a docker container to my expereinces.

Personally I am using Visual Studio Code [DevContainers](https://code.visualstudio.com/docs/devcontainers/containers), which allows me to run Visual Studio Code natively on my host while programing *"remotely"* inside a architecture agnostic container. Thanks to an extension provided my Microsoft this is easy and nearly transparent for the user.

Below is a sample DevContainer Definition I am using for the work with quiling. First we have the `devcontainer.json` specifying the UI options and installed extensions being available in the IDE. Notice that the extions are running inside the container, thus even if a VS Code extension is malicious it does not effect our host, which is a nice side-effect of this construct!

```json
// For format details, see https://aka.ms/devcontainer.json. For config options, see the
// README at: https://github.com/devcontainers/templates/tree/main/src/go
{
  "name": "Qiling DevContainer",
  "dockerComposeFile": "docker-compose.yml",
  "service": "devcontainer",
	"remoteUser": "analyst",
  "workspaceFolder": "/workspaces/content",
  "shutdownAction": "stopCompose",
  "customizations": {
    "vscode": {
      "extensions": [
        "ms-python.python",
        "ms-python.vscode-pylance",
        "ms-vscode.cpptools"
      ],
      "settings": {
        "python.defaultInterpreterPath": "/usr/local/bin/python",
        "terminal.integrated.defaultProfile.linux": "bash"
      }
    }
  },
  "mounts": [
    "source=${localWorkspaceFolder},target=/workspace/content,type=bind,consistency=cached"
  ]
  // uncomment if you need to install additional requirements or need version pinning
  // "postCreateCommand": "pip install -r requirements.txt || true"
}

```

Next, there is the `docker-compose.yaml` describing the container / service from a high level perspective:

```yaml
version: '3.8'
services:
  devcontainer:
    build: 
      context: ..
      dockerfile: ./.devcontainer/Dockerfile

    volumes:
      - ../:/workspaces/content:cached     

    command: sleep infinity

  ruff:
    image: ghcr.io/astral-sh/ruff:0.8.1-alpine
    command: sleep infinity
    volumes: 
    - ../:/workspaces/content
```

And finally we have the `dockerfile` defining the actual installation of Python and quiling libraries.

```docker
FROM --platform=linux/amd64 python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# Core system dependencies for Qiling
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    cmake \
    pkg-config \
    libglib2.0-dev \
    libpixman-1-dev \
    libssl-dev \
    libffi-dev \
    gdb \
    wget \
    curl \
    vim \
    nano \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip tooling
RUN pip install --upgrade pip setuptools wheel

# Install Qiling and its ecosystem
RUN pip install \
    qiling \
    unicorn \
    capstone \
    keystone-engine \
    pyelftools

# Create non-root user (recommended)
ARG USERNAME=analyst
ARG USER_UID=1000
ARG USER_GID=1000

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && chown -R $USERNAME:$USERNAME /home/$USERNAME

USER $USERNAME
WORKDIR /workspace
```
  
The files just have to be placed in a directory called `.devcontainers` inside our project. Then if opened with Visual Studio Code the magic will happen. The IDE detects the container definition, builds the container environment, mounts the directories and connects to the container. Now everything happens inside the container: Execution of code, installation of additional libraries, etc.

If we close Visual Studio Code, the container is terminated as well. Thus, we have a architecture agnostic development environment and an additional layer of security due to the containerization. Also the container defintion persits and is reproducable. So if we change our machine at any time there will be no issues like *"My software compiles on machine A but not on B"*.

We can create more DevContainers for all the programming languages and use-cases we need. So to wrap up, software development is woking perfect on MacOS and even the usage of Apple Silicon does not pose any disadvantage. Thanks to Apple Virtualization framework the emulation is fast and not really noticable for small to mid-sized project.


# But is Apple Silicon a Smart Choice for Security workflows?

If you are familiar with the field of cyber security you are propably aware of that the most forensic tools are written for `x86_64`. There is, e.g., an Apple Silicon compatible version of Kali Linux, however `shellter` would not run on that. The installed packages differ and they do not provie the full experience as the `x86_64` pendants. Even worse, **REMNux** and **SIFT Workstation** does not provide ÀRM64` compatible images as well. For many other tools re-compilation is required, which often ends in a hit-or-miss scenario.

Sounds very teribble, right? - And yes it is, at least up to some point.

For my security workflows and use-cases I found workarounds working quite well for me. I will present them in the next sub-sections. Still remember, that this is personal and very subjective. You may not have the same luck to cover all your requirements when using Apple Silicon based devices.


## Malicious Document Analysis

Still in 2025, analyzing malicious documents is a relevant topic. To this end, we require tools commonly bundles with **REMNux**. E.g., `pdfid.py`, `pdf-parser.py`, `oletools` and some others. My workaround to be able to access these tools is `docker` again. Since malicious document analysis does not require a lot of computational resources, we can use the `x86_64` emulation layer of docker. A simple REMNux container can be started for the analysis. For the sake of convinience, I mapped the command inside a custom shell function such that I need to call `remnux-shell` only.

```
 137 │ ## Setup of Custom docker containers
 138 │ remnux-shell() {
 139 │   docker run --rm -it --name "REMNux" \
 140 │     -u "$(id -u):$(id -g)" \
 141 │     -v "$PWD:/mnt/analysis" \
 142 │     -w /mnt/analysis \
 143 │     remnux/remnux-distro:focal \
 144 │     bash
 145 │ }
 ```

Now, I am inside a REMNux container and have access to all the tools required for malicious document analysis. The performance is very well. I did not noticed any disadvantages compared to a 2 vCPU / 4 GB RAM REMNux VM. Sure, the containerization is a weaker isolation then using a virtual machine, however in my opinion the architectural break from `x86_64` to `ARM64` balances this issue. Also typically malicious document based malware is script based and does not try to execute any VM escapes.

So to sum up, analyzing malicious documents is possible on Apple Silicon. We are able to use all the tools, we know from classic REMNux without noticing any performance penalty yield by the M series CPU.

## Script Based Malware

Another common threat is script based malware. To analyze it we need a text editor and language interpreters like ones for `JavaScript`, `Powershell` and `VB` script. Luckily all these interpreters does not require a lot of performance. Hence, we can either use **REMNux** inside a docker container, again as described in the previous section; or run a **Windows 11 ARM64** virtual machine. Additionally, Powershell is available as native application if you like the risk to analyse directly on your host.

So, also here, I did not experiences any restricted which avoided me from doing my job. Analysis of script based malware is totally doable on Apple Silicon.

## Classic PE-file Malware

There are three major types of malware, we may encounter during our analysists life when speaking about classic PE-file based malware.

1. Classic Win32 native applications
2. .NET based malware samples
3. Actual Python code packed to binary by e.g., PyInstaller or Nuitka

Let us discuss them one ofter another, starting with the last one. 

Python based malware is actually not really a classic PE-file malware. Several unpackers does exist to generate valid Python code from a given sample. Once this is done, the code can be easily investigated from the inside a text editor. The analysis may be supported using Python to evaluate part of the sample. All this is possible on Apple Silicon without any restrictions. The required tools are either running in the cloud or can be emulated inside Windows 11 ARM or docker.

NET based malware is very similar. Since .NET malware is not running on the host natively there are no restrictions by the CPUs architecture. The required .NET runtime does exist for docker, Windows 11 ARM and even MacOS directly. Also the required analysis tools like `DnSpyEx` can be executed from a Windows 11 ARM virtual machine. I did not encountered any issues when analysing these type of samples. Neither during static nor dynamic analysis.

The classic Win32 native applications are the hardest to analyse on Apple Silicon. The support for static analysis is quite well. All the major Disassembler and Decompiler like IDA, Binary Ninja and Ghidra are available on MacOS for Apple Silicon. There is even a very good HexEditor named ImHex. So, static analysis is absolut no difference compared to working on normal PC.

The issues starts when trying dynamic analysis and debugging. Using the Windows 11 ARM emulation layer, we can execute the malware in a sandboxed environment without problems. The malware will execute and generate its artifacts, we can try to obsereve them with, e.g., `regshot`and `procmon64.exe`, however this is only the half truth. Most modern malware uses Anti-Debugging and Anti-Analysis techniques. Commonly monitoring tools like `regshot` and `ProcMon` were detected and the malware does nothing! A common solution to this is dynamic debugging and patching during runtime. I.e., we start the sample in `x32dbg` / `x64dbg`, setting breakpoints, and let the malware run. This allows for e.g., easy unpacking, and speeds up analysis a lot.
However, this is just not possible on Apple Silicon. **You can not Debug an x86_64 application on ARM64 device**. For many people this is a show stopper and in the first place it was for me as well. Now, I found some workarounds and arguments, why it is still reasonable to analyse this kind of samples on M series CPUs.

Let me summarize them below:

- Dynamic Analysis of unknown samples is never a good idea even in isolated environment. So static analysis comes first.
- Once we have a rough understanding of the sample from the initial static analysis, emulaion by using e.g., `sogen` or `quiling` is not really slower than debugging the sample. Consider that during debugging you often have to start from the beginning just become you hit an anti-analysis trap like a Debugger check.
- Restricting yourself to emulation and static analysis increases your leraning curve and can teach you a lot. Also no execution is always the safer option, especially with ransomware
- If really required, nowadays cloud based VMs are cheap to get on AWS or Azure. Also a used cheap `x86_64` device connected via RDP is an option in emergency cases.

So I guess I made my point clear. The situation is not perfect on Apple Silicon but at least for my use-cases I was able to handle that scenario up to a point where I can accept the situation at least.


# Any other benefits of using Apple Silicon

In the last section I complained a lot about the issues with debugging and dynamic code analysis of `x86_64` applications on Apple Silicon. So let me now summarize some aspects I love while working on a MacBook.

First of all the mobility is superior. The build quality, built-in display, and battery endurance allows me to take the laptop nearly to any spot on this planet without being afraid of going out of energy. The OS and user experience is well designed and inuitive. Anyways, the best is the power of the M series CPU itself! Newer models are able to run local LMMs using, e.g., LM Studio. So we can host our own private model, which can even be used when offline and no internet connection is aailable or desired. This can sometimes speed up analysis even more than any Intel or AMD chip could do: ;-)

Also, if you are like me not a security-only person, the availability of software is generally very good on MacOS. I am hobby photographer and video editor and love the devices performance with respect to that!


# Summary

Initially I raised the Question *Is Apple Silicon a Smart Choice for Security Analysts?*. The answer to this question is very subjective. While there are advantages like build quality, battery endurance and the general tendency to work in the cloud, many disadvantages exist. Often an Apple Silicon user needs to re-compile software or run it inside a container just because it is not natively supported on the host. For me I figured out workarounds for all my use-cases and security workflows. Since I am also a photographer, videographer and owner of an iPhone, the move to Apple Silicon was worth it. Other operating systems does have other issues. E.g., Linux was perfect for security purposes, but editing photos or cutting videos was solely not possible. On Windows all seems to be possible, however laptops satisfying the requirements of mobility and power were just not available to my knowledge. This would had end me up in having a tower PC for video editting and photography and a smaller laptop for day to day business and mobility. All this introduce syncronization hazzles and other issues. So to sum up on my MacBook I can do all the things I like in one device. The disadvantage of not beeing able to debug `x86_64` can be mitigated by using VMs in the cloud. So all in all it was the right descition for me, but the move and recommendation for Apple Silicon heavily depends on the personal situation. Before changing your hardware you should carefully think about what you want to do with your device, and which tools you require for that purpose.

---
---
