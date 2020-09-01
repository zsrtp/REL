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

#include <display/console.h>

namespace mod
{
    void main()
    {
        libtp::display::setConsole(true, 25);
        libtp::display::print(1, "Hello World!");

        return;
    }
}  // namespace mod