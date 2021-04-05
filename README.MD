

# Twilight Princess - REL
This is a template repository for you to create your very own Twilight Princess mod!

## Project Structure
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

This repository provides you with a solid start, you should use the predefined main function as an entry point to your mod...
Please check Lines 12 through 23 in the Makefile to change some of the definitions and names.

You can refer to the [Randomizer](//github.com/zsrtp/Randomizer) Project for reference.

## Coding guidelines

Our coding guidelines, and other useful information, can be found in our wiki at [wiki.zeldatp.net](//wiki.zeldatp.net/Dev).
Please refer to

---
This mod is powered by [libtp_rel](//github.com/zsrtp/libtp_rel) and licensed under [GPLv3](/LICENSE) | (C) [AECX](//github.com/AECX), [LunarSoap](//github.com/lunarsoap5), [Zephiles](//github.com/Zephiles)
