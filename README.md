# psvkirk

This repo contains two utilities that expose some PS Vita kernel functions related to new Kirk cryptography.  
Those functions internally communicate with F00D.  
Kernel functions are exposed as client - server API.  
  
## driver module
First utility is a driver module that should be loaded with taihen.
It imports these functions (some names are just mine since we have only NIDs):  
* ksceSblSsMgrGenerate40
* ksceSysrootGetElfInfo
* ksceSblSmCommStartSm1
* ksceSblSmCommCallFunc
* ksceSblSmCommStopSm
  
It exports these functions:  
* psvkirkGenerate10
* psvkirkGenerate20
* psvkirkCallService1000B
  
These functions are reversed partial reimplementation of subroutines from SceSblGcAuthMgr module.  
For additional information you can check https://github.com/motoharu-gosuto/psvcmd56  
 
# user application
Second utility is a user application that can be installed normally through VitaShell.  
This application acts as a server that exposes functions from kernel module.  
The idea is to connect from client application to PS Vita and use it as a black box with Kirk cryptography (F00D).
  
# how is this used?
Client code is also implemented and is part of my previous project https://github.com/motoharu-gosuto/psvcd  
I have reversed most of CMD56 custom initialization protocol that PS Vita uses to initialize game carts.  
I would suggest to check everything on henkaku wiki.  
https://wiki.henkaku.xyz/vita/Game_Card  
https://wiki.henkaku.xyz/vita/F00D_Commands
With this I was finally able to read game carts with custom board without having to connect PS Vita instance to the board.
You may ask: "So what? You previously said that your project was firmware independent. But now you are actually using taihen plugin." Yes - that is true. However previously I did not know anything about CMD56 protocol so PS Vita itself was acting like black box that initialized the game cart. This time Kirk cryptography (F00D) acts as a black box. And this whole setup is done so that it has some potential and field for further research of Kirk cryptography (F00D).

# next goals and other usages
* Second milestone was now reached. CMD56 protocol is reversed.  Next milestone is a much bigger beast. To completely get rid of this proxy tool we need to understand what is happening in F00D.  
* Other things that I can try now is to patch SceSblGcAuthMgr so that it ignores CMD56 step. This will allow me to do a one to one dump and store it to normal SD or MMC card. I can then solder standard slot to motherboard and try to run it.  
* I am not quite sure but this information may also help folks that are developing Memory Stick adapter.  
* Recently I had reversed lots and lots of Sdif and related drivers code and plan to release some Sdif API soon.  

