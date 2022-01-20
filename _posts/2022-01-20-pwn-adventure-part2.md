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

