---
title: PwnAdventure Part1 - Setup
date: 2022-01-19 12:02:00 +0530
categories: [Pwn]
tags: [pwn,game hacking,setup]
pin: true
---

![Logo](/assets/pwn-adventure-logo.png)

## What is this series about ?
---
I recently came across LiverOverflow's youtube [series](https://www.youtube.com/watch?v=RDZnlcnmPUA&list=PLhixgUqwRTjzzBeFSHXrw9DnQtssdAwgG) on [PwnAdventure3](https://www.pwnadventure.com/). I got interested in this because it involves game hacking which I think is very cool. Please note that this series will not be different from that of LiveOveflow's and this blog is just a recording of my journey. I hope you enjoy it!

<br>

## What is PwnAdventure ?
---
PwnAdventure is a MMORPG which is intentionally vulnerable to hacks and this was made for a CTF which I think is really cool. It was originally made for education game developers about vulerabilities found in video games.
<br>

## Setup
---
* Originally the game server was hosted by the organisers during the time of the CTF but it is currently down so I decided to host it on my own server.
* I followed the same steps as LiveOverflow in this [video](https://www.youtube.com/watch?v=VkXZXwQP5FM&list=PLhixgUqwRTjzzBeFSHXrw9DnQtssdAwgG&index=2)
* Among all the options he shows I chose to create a droplet on DigitalOcean and used Docker to run the server from the same git [repository](https://github.com/LiveOverflow/PwnAdventure3) that LiveOverflow uses.
<br>

## Exact Steps
---
* I registered an account on DigitalOcean using a referral link to get 100$ in credits for free. You can use this [link](https://m.do.co/c/dd4389e88fc1) to get yourselves 100$ too.
* Then I created a droplet on DigitalOcean with the following specifications:
    * Name: pwn3
    * Region: Bangalore
    * Memory: 4GB
    * Image: Ubuntu 20.04
    * CPU: 2 vCPU
    * Disk: 80GB
    * Monitoring: on
    * Cost: $24/month
    * Authentication: SSH
* After creating the droplet I was given the IP address of the droplet. I SSHed into the droplet as root.
* I then followed the instructions for installation as mention in this [repository](https://github.com/LiveOverflow/PwnAdventure3) and installed the server.
* I then started the server by running the command - `docker-compose up -d` to run the server in detached mode.
> I came across and error while installing which was `bind source path does not exist: ./postgres-data` which is also mentioned in this issue [here](https://github.com/LiveOverflow/PwnAdventure3/issues/31). It is essentially solved by creating a directory `postgres-data`.
<br>

## Installing Game Client on Windows
---
For installing the game client of windows download the client files from [here](https://www.pwnadventure.com/PwnAdventure3_Windows.zip) and extract it.
Edit the `C:\Windows\System32\drivers\etc\hosts` file (with admin priviliges) and add the following lines:
```
IP.IP.IP.IP master.pwn3
IP.IP.IP.IP game.pwn3
```
Here replace the `IP.IP.IP.IP` with the IP address of the droplet.Now open the serevr.ini file which is in the game folder and change it to:
```
[MasterServer]
Hostname=master.pwn3
Port=3333

[GameServer]
Hostname=
Port=3000
Username=
Password=
```
The server has been configured now open the game and register yourself. After registering you get a team hash which can be used to join your team by other players.
<br>

## Installing Game Client on Linux
---
For installing the game client of linux download the client files from [here](https://www.pwnadventure.com/PwnAdventure3_Linux.zip) and extract it.
Edit the `/etc/hosts` file (with root priviliges) and add the following lines:
```
IP.IP.IP.IP master.pwn3
IP.IP.IP.IP game.pwn3
```
Here replace the `IP.IP.IP.IP` with the IP address of the droplet.Now open the serevr.ini file which is in the game folder and change it to:
```
[MasterServer]
Hostname=master.pwn3
Port=3333

[GameServer]
Hostname=
Port=3000
Username=
Password=
```
The server has been configured now open the game and register yourself. After registering you get a team hash which can be used to join your team by other players.
<br>