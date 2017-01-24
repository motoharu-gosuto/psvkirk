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
The idea is to connect from client application to PS Vita and use it as a black box with Kirk cryptography.
  
# how is this used?
Client code is also implemented and is part of my previous project https://github.com/motoharu-gosuto/psvcd  
I have reversed most of CMD56 custom initialization protocol that PS Vita uses to initialize game carts.
With this I was finally able to read game carts with custom board without having to connect PS Vita instance to the board.
You may ask: "So what? You previously said that your project was firmware independent. But now you are actually using taihen plugin." Yes - that is true. However previously I did not know anything about CMD56 protocol so PS Vita itself was acting like black box that initialized the game cart. This time Kirk cryptography (F00D) acts as a black box. And this whole setup is done so that it has some potential and field for further research of Kirk cryptography (F00D).

