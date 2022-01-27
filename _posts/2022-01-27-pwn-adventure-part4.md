---
title: PwnAdventure Part4 - Function Hijacking
date: 2022-01-27 12:02:00 +0530
categories: [Pwn]
tags: [pwn,game hacking,LD_PRELOAD,dlsym]
pin: true
---

## Developing our First Hack
---
In this post I'm going over our first step to develop a hack. The way we are going to do it is we are going to overwrite functions in the `libGameLogic.so` by writing our own library and the `LD_PRELOAD` in it. This is why we built the header file to get the correct offsets of objects and getting the function definitions.  

## Testing LD_PRELOAD
---
Let's test our `LD_PRELOAD` function hooking by hooking a simple function and console logging the output. So what we're going to do is hook the `Player::SetJumpState(bool b)` function and just outputing the value of b to check if we are able to hook the function.  
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

void Player::SetJumpState(bool b)
{
    printf("[*] SetJumpState(%d)\n",b);
}
```
This is how we are going to hook the function and check the value. We have to be careful how we compile it as we have to compile it a shared library and make it position independant.  
```bash
g++ jumpHook.cpp -std=c++11 -shared -o myLib.so -fPIC
```
Here `-shared` is to signify that we want it to be compiled as a shared object file and `-fPIC` so that it is position independant.  

> Keep in mind that we are overwriting the function body entirely and not calling the functions being called after this i.e we are not sending the server information that we are jumping so we would only be jumping in our client and would'nt appear to be jumping to others.  

## Our Target Function
---
Since we know that we can hook any function we'll search for a function which is kinda useless and can be called upon easily. Liveoverflow finds the function `World::tick(float f)`. We can hook this and see what argument it is getting.  
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

void World::Tick(float f)
{
    printf("[tick] %0.2\n",f);
}
```
After hooking the function we see that its just a normal `tick` function and is being executed quite freqeuently about 2 times per sec.  

![tick](/assets/postimg/pwnadv4/tick.png)  

## Enter Dlsym
---
Since now we can overwrite functions lets see how we can write data in `.bss` of the other libraries. We will use the `dlsym` function. This takes 2 arguments a handle and a symbol. The handle is for any open dynamic library and symbol is the symbol whose address we want. for the handle we will use the special argument `RTLD_NEXT` which finds the next occurence of the symbol.  
We'll use `dlsym` to find the address of the `GameWorld` object which we saw was a global variable in the `.bss`.  

## Getting our Player Object
---
For this part we would have to look at the classes in depth and see the relations between them. So I just followed Liveoverflow's example of how we got to the player object from the `GameWorld` object. Just as how he did we're going to get our `Player` object and try to print our name and mana.
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

void World::Tick(float f)
{
    ClientWorld *world = *((ClientWorld **)(dlsym(RTLD_NEXT,"GameWorld")));
    IPlayer *iplayer = world->m_activePlayer.m_object;
    printf("[LO] IPlayer->GetPlayerName: %s\n",iplayer->GetPlayerName());
    Player *player = ((Player *)(iplayer));
    printf("[LO] player->m_mana: %d\n",player->m_mana);
}
```
We see that this function updates frequently giving us sort of a live update each time we use our mana.

![info](/assets/postimg/pwnadv4/info.png)

## Our First Hack
---
We'll use this player object to increase our player speed and get our speed hack! Somehow the server trust the client in the position it provides and our speed hack is visible to other players as well.

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

void World::Tick(float f)
{
    ClientWorld *world = *((ClientWorld **)(dlsym(RTLD_NEXT,"GameWorld")));
    IPlayer *iplayer = world->m_activePlayer.m_object;
    Player *player = ((Player *)(iplayer));
    player->m_walkingSpeed = 99999;
}
```
