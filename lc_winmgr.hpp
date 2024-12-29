/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#ifndef LC_WINMGR_HPP
#define LC_WINMGR_HPP

#ifdef _WIN32
#include "lc_winmgr_windows.hpp"
#else
#include "lc_winmgr_ncurses.hpp"
#endif

#endif