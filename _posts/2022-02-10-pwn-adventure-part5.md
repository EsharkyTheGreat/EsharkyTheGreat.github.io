---
title: PwnAdventure Part5 - More Hacks!!
date: 2022-02-10 16:48:00 +0530
categories: [Pwn]
tags: [pwn,game hacking,LD_PRELOAD,dlsym]
pin: true
---

## Developing More Hacks
---
In the previous post I went over `LD_PRELOAD` to hijack functions and created the speed hack. In this post I'm going over and understanding other hacks that LiveOverflow made i.e fly hack and teleportation hack.

## Creating our Fly Hack
---
Like the previous hack we can just hook the `World::tick()` function access the global `GameWorld` variable and edit `m_jumpSpeed` and `m_jumpHoldTime` of our player object to create a sort of fly hack.  
```cpp
#include "libGameLogic.h"
#include <set>
#include <dlfcn.h>
#include <map>
#include <functional>
#include <string>
#include <cstring>
#include <vector>
#include <cfloat>
#include <memory>
#include <stdint.h>

bool Player::CanJump()
{
    return 1;
}
void World::Tick(float f)
{
    ClientWorld* world = *((ClientWorld**)(dlsym(RTLD_NEXT, "GameWorld")));
    IPlayer* iplayer = world->m_activePlayer.m_object;
    Player* player = ((Player*)(iplayer));
    player->m_walkingSpeed = 99999;
    player->m_jumpSpeed = 999;
    player->m_jumpHoldTime = 99999;
}
```  

