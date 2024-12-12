---
layout: post
title: Windows Core Proccesses
subtitle: An Overview on Windows Core Processes
tags: [Windows, DFIR]
# cover-img: /assets/img/path.jpg
# thumbnail-img: /assets/img/thumb.png
# share-img: /assets/img/path.jpg
# comments: true
# mathjax: true
author: TekCookie75
---

# Windows Core Processes

In Digitial Forensics and Incident Response (DFIR), the most difficult task is in distinguishing the *good* from the *bad*. This task becomes even more difficult since adversaries try to blend in the commonly found process names on Windows operating systems to hide in the plain sight. In this short blog post, we will discuss some of the core Windows processes found on any system. We will shortly discuss the expected behaviour and indications of these system processes to may help in identifying suspicious ones.

## Boot Secuence and Process overview

The first process launched by Microsoft windows is `System.exe`. According to the offical documentation `System.exe` is responsible for the following:
*The System process (process ID 4) is the home for a special kind of thread that runs only in kernel mode a kernel-mode system thread. System threads have all the attributes and contexts of regular user-mode threads (such as a hardware context, priority, and so on) but are different in that they run only in kernel-mode executing code loaded in system space, whether that is in Ntoskrnl.exe or in any other loaded device driver. In addition, system threads don't have a user process address space and hence must allocate any dynamic storage from operating system memory heaps, such as a paged or nonpaged pool.*

Afterwards, the `System.exe` will spawn the `csrss.exe`, the `wininit.exe`, and the `winlogon.exe` via the *Session Manager Subsystem* according to the following depiction:

![WindowsCoreProcesses](/assets/img/_posts/2024-09-28-Windows-Core-Processes/Windows-Core-Processes.png)

The depicted processes are shortly descriped in the table below.

| **Process** | **Description** |
| ----------- | --------------- |
| `system.exe`  | - always PID 4  <br/>- first process created in boot sequence <br/>- run in privileged kernel mode only |
| `smss.exe`    | - `system.exe` is always the parent! <br/>- two instances spawn; SESSION 0 and SESSION 1 <br/>- process terminates after execution! |
| `csrss.exe`   | - spawned by `smss.exe` <br/>- does not have parent <br/>- two instances spawn; SESSION 0 and SESSION 1 <br/>- provides Win-API <br/>- Handles power cycles and Scheduling/Threads |
| `wininit.exe` | - spawned by `smss.exe` <br/>- does not have parent <br/>- only runs in privileged SESSION 0 |
| `services.exe`| - spawned by `wininit.exe` <br/>- handles services <br/>- only runs in privileged SESSION 0 |
| `lsass.exe`   | - spawned by `wininit.exe` <br/>- Local Security and Account Sub-System <br/>- only runs in privileged SESSION 0 |
| `lsaiso.exe`  | - spawned by `wininit.exe` <br/>- Part of Local Security and Account Sub-System <br/>- only runs in privileged SESSION 0 <br/>- provides sandbox features for `lsass.exe` |
| `svchost.exe` | - spawned by `services.exe` <br/>- runs tasks from *.dll files <br/>- can have various owners depending on the concrete service <br/>- always runs with flag `-k`|
| `winlogon.exe` | - spawned by `smss.exe` <br/>- does not have parent <br/>- only runs in user SESSION 1 <br/>- login management <br/>- loads profile from `NTUSER.DAT` and executes Shell Environment, e.g., `explorer.exe` |
| `userinit.exe` | - spawned by `winlogon.exe` <br/>- handles initalization of user profile <br/>- only runs in user SESSION 1 |
| `explorer.exe` | - spawned by `userinit.exe` <br/>- user shell <br/>- only runs in user SESSION 1 |

All processes created by the user later on will have `explorer.exe` as parent process.
