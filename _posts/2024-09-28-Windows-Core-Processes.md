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

![Core-Processes](/assets/img/_posts/2024-09-28-Windows-Core-Processes/Windows-Core-Processes.png)

The depicted processes are shortly descriped in the table below.

| **Process** | **Description** |
| ----------- | --------------- |
| `system.exe`  | <ul><li>always PID 4</li><li>first process created in boot sequence</li><li>run in privileged kernel mode only</li></ul> |
| `smss.exe`    | <ul><li>`system.exe` is always the parent!</li><li>two instances spawn; SESSION 0 and SESSION 1</li><li>process terminates after execution!</li></ul> |
| `csrss.exe`   | <ul><li>spawned by `smss.exe`</li><li>does not have parent</li><li>two instances spawn; SESSION 0 and SESSION 1</li><li>provides Win-Api</li><li>Handles power cycles and Scheduling/Threads</li></ul> |
| `wininit.exe` | <ul><li>spawned by `smss.exe`</li><li>does not have parent</li><li>only runs in privileged SESSION 0</li></ul> |
| `services.exe`| <ul><li>spawned by `wininit.exe`</li><li>handles services</li><li>only runs in privileged SESSION 0</li></ul> |
| `lsass.exe`   | <ul><li>spawned by `wininit.exe`</li><li>Local Security and Account Sub-System</li><li>only runs in privileged SESSION 0</li></ul> |
| `lsaiso.exe`  | <ul><li>spawned by `wininit.exe`</li><li>Part of Local Security and Account Sub-System</li><li>only runs in privileged SESSION 0</li><li>provides sandbox features for `lsass.exe`</li></ul> |
| `svchost.exe` | <ul><li>spawned by `services.exe`</li><li>runs tasks from *.dll files</li><li>can have various owners depending on the concrete service</li><li>always runs with flag `-k`</li></ul> |
| `winlogon.exe` | <ul><li>spawned by `smss.exe`</li><li>does not have parent</li><li>only runs in user SESSION 1</li><li>login management</li><li></li>loads profile from `NTUSER.DAT` and executes Shell Environment (e.g., `explorer.exe`</ul> |
| `userinit.exe` | <ul><li>spawned by `winlogon.exe`</li><li>handles initalization of user profile</li><li>only runs in user SESSION 1</li></ul> |
| `explorer.exe` | <ul><li>spawned by `userinit.exe`</li><li>user shell</li><li>only runs in user SESSION 1</li></ul> |

All processes created by the user later on will have `explorer.exe` as parent process.