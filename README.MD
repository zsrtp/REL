

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
│   ├───banner.raw          // Game banner for the GCI
|   ├───icon.raw            // Game icon for the GCI
│   ├───*.lst          	    // Symbol:Address pairs for each version of the game
├───bin/                    // Binary files and scripts
│   ├───elf2rel             // Linux Binary of elf2rel
│   ├───elf2rel.exe         // Windows "
│   ├───gcipack.py          // Packs a REL into a GCI
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
Please check Lines 12 through 23 in the Makefile to change some of the definitions and names.

You can refer to the [Randomizer](//github.com/zsrtp/Randomizer) Project for reference.

## Wiki
---
### General
Our [wiki](//wiki.zeldatp.net) is meant to be a central source of information for TP with a slightly technical focus we provide the most crucial information such as Stages & Rooms or item ids. If you're looking for information you should be looking there or ask in the [dev discord](//discord.gg/CsDF9hY).

### Coding guidelines
Our coding guidelines, and other useful information, can be found in our wiki at [wiki.zeldatp.net](//wiki.zeldatp.net/Dev).
If you intend to share this code with the @zsrtp community, please follow the guidelines as strictly as possible.

## Building
---
**Dependencies**
  * [DevkitPPC] comes with [devkitPro](//github.com/devkitPro/installer/releases)
  * [Python3](//www.python.org/downloads) (should be added to PATH or you will likely need Makefile adjustments)
  * Optional: [Visual Studio Code](//code.visualstudio.com) with [GC Settings](//wiki.zeldatp.net/Dev:Visual_Studio_Code)

**Compiling**

*devkitPro comes with it
s own MSys2 shell, it is recommended to use it for compilation.

This is an example of how to build for the NTSC-U version of the Game
```
$ cd /c/Path/To/REL
$ make us
main.cpp
cxx.cpp
memory.cpp
patch.cpp
rel.cpp
tools.cpp
timer.cpp
console.cpp
restfpr_x.s
restgpr_x.s
linking ... Randomizer.us.elf
output ... Randomizer.us.rel
packing ... Randomizer.us.gci
```
The `Randomizer.us.gci` (other versions are: `jp` and `eu`) file is now containing our custom REL. Load it with the REL Loader cheat or a hacked save file that contains the loader, it can be found on the [rando](//rando.zeldatp.net) homepage.

---
This mod is powered by [libtp_rel](//github.com/zsrtp/libtp_rel) and licensed under [GPLv3](/LICENSE) | (C) [AECX](//github.com/AECX), [LunarSoap](//github.com/lunarsoap5), [Zephiles](//github.com/Zephiles)
