

# Twilight Princess - REL
This is a template repository for you to create your very own Twilight Princess mod and provide a simple start to write your code. Kind of like a "hello world" for TP.

## Project Structure
---
```
REL
├───externals/              // Submodules or other dependencies are placed here
│   │   ├───libtp_rel/
│   │   │   ├───include/    // Library Header files
│   │   │   ├───source/     // Library source files
├───assets/                 // Additional resources that are not code
│   ├───gc_banner.raw       // Game banner for the GCI
|   ├───wii_banner.raw      // Game banner for the Wii save
|   ├───icon.raw            // Game icon for the GCI
│   ├───*.lst          	    // Symbol:Address pairs for each version of the game
├───bin/                    // Binary files and scripts
│   ├───elf2rel             // Linux Binary of elf2rel
│   ├───elf2rel.exe         // Windows "
│   ├───gcipack.py          // Packs a REL into a GCI
│   ├───nandpack.py         // Packs a REL into a Wii save
├───docs/                   // Doxygen Output folder; can be used for GitHub pages - change in doxygen.conf
├───include/                // Your Header (.h) files
├───source/                 // Your Source (.cpp) files
├───Makefile                // Build script
├───.clang-format           // clang-format configuration file
├───doxygen.conf            // doxygen configuration file
```

## Getting started
---
This repository provides you with a solid start, you should use the predefined main function as an entry point to your mod...
Please check Lines 19 through 30 in the Makefile to change some of the definitions and names.

You can refer to the [Randomizer](//github.com/zsrtp/Randomizer) Project for reference.

## Wiki
---
### General
Our [wiki](//wiki.tprandomizer.com) is meant to be a central source of information for TP with a slightly technical focus we provide the most crucial information such as Stages & Rooms or item ids. If you're looking for information you should be looking there or ask in the [dev discord](//discord.gg/aZx8ZFcSPy).

### Coding guidelines
If you intend to share this code with the @zsrtp community, please follow the [guidelines](//wiki.tprandomizer.com/index.php?title=Dev:Coding_Guidelines) as strictly as possible.

## Building
---
**Repository**

*You need to have git installed ([windows](https://git-scm.com/download/win))*

Open a CMD and navigate to where you want your code to be:
```
C:\>mkdir Code
C:\>cd Code
C:\Code>git clone https://github.com/zsrtp/REL.git
Cloning into REL
remote: Enumerating objects: 132, done.
remote: Counting objects: 100% (132/132), done.
remote: Compressing objects: 100% (87/87), done.
remote: Total 132 (delta 56), reused 98 (delta 29), pack-reused 0
Receiving objects: 100% (132/132), 1.24 MiB | 6.45 MiB/s, done.
Resolving deltas: 100% (56/56), done.
```
Download and upate libtp_rel
```
C:\Code\REL> git submodule update --init --remote
```
Done.

**Dependencies**
  * DevkitPPC comes with [devkitPro](//github.com/devkitPro/installer/releases)
  * [Python3](//www.python.org/downloads) (should be added to PATH or you will likely need Makefile adjustments)
  * [pycryptodomex](https://pypi.org/project/pycryptodomex/) (For Wii only, dependency of [`nandpack.py`](https://github.com/kipcode66/wii_tools))
  * Optional: [Visual Studio Code](//code.visualstudio.com) with [GC Settings](//wiki.tprandomizer.com/index.php?title=Dev:Visual_Studio_Code)

**Compiling**

*devkitPro comes with its own MSys2 shell, it is recommended to use it for compilation.

This is an example of how to build for the NTSC-U version of the Game
```shell
$ cd /c/Path/To/REL
$ make us
main.cpp
cxx.cpp
memory.cpp
patch.cpp
rel.cpp
tools.cpp
timer.cpp
stages.cpp
console.cpp
card.cpp
color_utils.cpp
texture_utils.cpp
restfpr_x.s
restgpr_x.s
linking ... REL.us.elf
output ... REL.us.rel
packing ... REL.us.gci
```
The `REL.us.gci` (`REL.wus0.bin` for wii) (other versions are: `jp`, `eu`, `wus0`, `wus2`, `wjp`, and `weu`, as well as two other build target `gcn` and `wii` which build all the version for the specified platform) file is now containing our custom REL. Load it with the REL Loader cheat or a hacked save file that contains the loader, both of which can be found on the wiki [REL Loader](//wiki.tprandomizer.com/index.php?title=REL_Loader) page.

##### Injecting into an existing Wii save

If you wish to inject the mod into an existing Wii save instead of generating an empty save, you can use the `nandpack.py` script to do that. Here is an example:

```shell
$ ./bin/nandpack.py inject -i 3 -g us0 -f "REL Example" REL.wus0.rel data.bin REL.wus0.bin
```

Where:
- `-i 3`: inject the mod into the 3rd slot.
- `-g us0`: specify we're injecting into an NTSCU 1.0 save.
- `-f "REL Example"`: set the name of the slot to `REL Example`
- `REL.wus0.rel`: this is the file containing the mod itself that we want to inject into the save.
- `data.bin`: this is the save file we want to inject the mod into.
- `REL.wus0.bin`: this is the resulting save file with the mod injected into it.

---
This mod is powered by [libtp_rel](//github.com/zsrtp/libtp_rel) and licensed under [GPLv3](/LICENSE) | (C) [AECX](//github.com/AECX), [LunarSoap](//github.com/lunarsoap5), [Zephiles](//github.com/Zephiles), [kipcode66](//github.com/kipcode66)
