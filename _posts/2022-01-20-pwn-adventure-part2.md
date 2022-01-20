---
title: PwnAdventure Part2 - Recon
date: 2022-01-20 12:15:00 +0530
categories: [Pwn]
tags: [pwn,game hacking,wireshark]
pin: true
---

![Logo](/assets/postimg/pwnadv2/wireshark-banner.png)

## Recon
---
What we'll be going over in this post is external recon of the game. What I mean by external recon is just getting and overview of how the game is working without going in detail and finding entry points for exploiting.
<br>
## In the Previous Post
---
We set up the game server and game client for both windows and linux in the previous post. One error that you might face which I faced was `libssl` and `libcrypto` was missing the game currently uses an older version of this library and I had to install it separately. [link](https://askubuntu.com/questions/1261614/ubuntu-20-04-libssl-so-1-0-0-cannot-open-shared-object-file-no-such-file-or-d)
<br>
## Libraries
---
Lets start first by looking the dynamic libraries linked with the game binary through the `ld` command.
![ld_ouptut](/assets/postimg/pwnadv2/ld_output.png)
We see many common libraries which are being used. There is `libpthread` which is used for threading. There is a custom `libGameLogic` library which might be useful. Using the file command on `libGameLogic` we see -
![file_output](/assets/postimg/pwnadv2/file_gamelogic.png)
The file has debug information which makes our life a lot easier. Looking at the other libraries we see `libcrypto` and `libssl` which might be used for encryption and TLS.
<br>
## Process Overview
---
Let's look at the process in Linux. Each process has a `pid` (process id). Lets see the process in `pstree` to see its child process and threads.
![pstree](/assets/postimg/pwnadv2/pstree.png)
Here we see all of the threads and their pids as well all of these components must be handling some sort of functionality.
<br>
## /proc/pid
The `/proc` is a a special directory which contains information about running processes. First we'll grab the pid through the command - 
```bash
ps aux | grep -i pwn
```
Then change the directory to `/proc/pid` you'll see something like this in the directory.
![proc](/assets/postimg/pwnadv2/proc.png)
Here the files represent different information about the process. E.g `cmdline`shows the cmdline arguments for running the process, `maps` show the virtual memory mapping of different libraries,stack,heap etc,the `fd` folder has info about the open file descriptors,`environ` has information about the environment variables.
![fd](/assets/postimg/pwnadv2/fd.png)
Upon inspecting the fd directory we see that there are standard file descriptors open like `STDIN`,`STDOUT`,`STDERR` etc and also file descriptors for packed textures and models.

