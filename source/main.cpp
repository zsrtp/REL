/**
 * @file main.cpp
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date YYYY-MM-DD
 *
 * @copyright Copyright (c) YYYY
 *
 */
#include <display/console.h>     // Contains a very neat helper class to print to the console
#include <main.h>
#include <patch.h>     // Contains code for hooking into a function
#include <tp/f_ap_game.h>

namespace mod
{
    Mod* gMod = nullptr;

    void main()
    {
        Mod* mod = new Mod();
        mod->init();
    }

    void exit() {}

    // Create our console instance (it will automatically display some of the definitions from our Makefile like version,
    // variant, project name etc.
    // this console can be used in a similar way to cout to make printing a little easier; it also supports \n for new lines
    // (\r is implicit; UNIX-Like) and \r for just resetting the column and has overloaded constructors for all of the
    // primary cinttypes
    Mod::Mod(): c( 0 )
    {
        i = 0;
    }

    void Mod::init()
    {
        /**
         * Old way of printing to the console
         * Kept for reference as its still being used by the new console class.
         *
         * libtp::display::setConsole(true, 25);
         * libtp::display::print(1, "Hello World!");
         */
        c << "Hello world!\n\n";

        gMod = this;
        // Hook the function that runs each frame
        return_fapGm_Execute =
            libtp::patch::hookFunction( libtp::tp::f_ap_game::fapGm_Execute, []() { return gMod->procNewFrame(); } );
    }

    void Mod::procNewFrame()
    {
        // This runs BEFORE the original (hooked) function (fapGm_Execute)

        // we can do whatever stuff we like... counting for example:
        i++;
        c << "\r"
          << "Frames: " << i;

        // return what our original function would've returned (in this case the return is obsolete since it is a void func)
        // And most importantly, since this is related to the frame output, call the original function at all because it may do
        // important stuff that would otherwise be skipped!

        return return_fapGm_Execute();     // hookFunction replaced this return_ function with a branch back to the original
                                           // function so that we can use it now
    }
}     // namespace mod