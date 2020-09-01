

# Twilight Princess - REL
This is a template repository for you to create your very own Twilight Princess mod!

## Project Structure
```
REL
├───externals/              // Submodules should be placed here
│   │   ├───libtp_rel/
│   │   │   ├───docs/       // Doxygen HTML documentation output
│   │   │   ├───include/    // Library Header files
│   │   │   ├───source/     // Library source files
├───assets/                 // Additional resources that are not code
│   ├───banner.raw          // Game banner for the GCI
|   ├───icon.raw            // Game icon for the GCI
├───bin/                    // Binary files and scripts
│   ├───elf2rel             // Linux Binary of elf2rel
│   ├───elf2rel.exe         // Windows "
│   ├───gcipack.py          // Packs a REL into a GCI
├───include/                // Your Header (.h) files
├───source/                 // Your Source (.cpp) files
├───Makefile                // Build script
├───.clang-format           // clang-format configuration file
├───doxygen.conf            // doxygen configuration file
```

## Getting started

This repository provides you with a solid start, you should use the predefined main function as an entry point to your mod...
Please edit line `#14` and `#15` of your Makefile in order to change the name of your project.

## Todo
- Create the guidelines document for contributors
	- Provide the necessary VSCode files and extensions
- Create a very basic tutorial on how to build this
---
This mod is powered by [libtp_rel](//github.com/zsrtp/libtp_rel) ([mirror](//code.zeldatp.net/?p=zsrtp/libtp_rel.git;a=tree)) and licensed under [GPLv3](/LICENSE) | (C) [AECX](//github.com/AECX), [LunarSoap](//github.com/lunarsoap5), [Zephiles](//github.com/Zephiles)