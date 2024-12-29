/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#pragma once

// Project includes
#include "lc_common.hpp"
#include "lc_consts.hpp"
#include "lc_strings.hpp"

// Platform includes
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// C++ std lib includes
#include <array>
#include <atomic>
#include <conio.h>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

// External variables that should be defined in client core
extern std::atomic<bool> send_msg_req;
extern std::atomic<bool> send_gby_req;
extern std::string       send_msg_body;
extern std::mutex        mtx;
extern std::atomic<bool> auto_signout;
extern std::atomic<bool> heartbeat_timeout;

constexpr int WIN_HEIGHT_MIN = 16;
constexpr int WIN_WIDTH_MIN  = 52;

constexpr int TOP_BAR_HEIGHT    = 1;
constexpr int BOTTOM_HEIGHT_MIN = 6;
constexpr int BOTTOM_HEIGHT_MAX = 12;
constexpr int SIDE_WIDTH_MIN    = ULOGIN_MIN_BYTES + 8;
constexpr int SIDE_WIDTH_MAX    = UNAME_MAX_BYTES + 8;

// Special key codes for Windows
constexpr int KEY_BACKSPACE = 8;
constexpr int KEY_TAB       = 9;
constexpr int KEY_ENTER     = 13;
constexpr int KEY_ESC       = 27;
constexpr int KEY_SEND      = 386; // Custom code for Shift+End

constexpr char welcome[] =
    "Welcome to LightChat Service (aka LiChat)!\n\
We support Free Software and Free Speech.\n\
Code: https://github.com/zhenrong-wang/lichat\n";

const std::string prompt      = "Input: ";
const std::string send_prompt = "([SHIFT][END] to send)";
const std::string top_bar_msg = "LiChat: Free Software (LIC: MIT) for Free Speech.";

enum winmgr_errors {
    W_NORMAL_RETURN = 0,
    W_ALREADY_INITED,
    W_NOT_INITIALIZED,
    W_COLOR_NOT_SUPPORTED,
    W_WINDOW_SIZE_INVALID,
    W_WINDOW_CREATION_FAILED,
};

struct input_wbuff {
    std::wstring wstr;
    size_t       bytes;
    input_wbuff() : wstr(L""), bytes(0) {};
};

// Represents a region of the console
struct ConsoleRegion {
    SHORT                  left;
    SHORT                  top;
    SHORT                  width;
    SHORT                  height;
    WORD                   attributes;
    std::vector<CHAR_INFO> buffer;

    ConsoleRegion() : left(0), top(0), width(0), height(0), attributes(0) {}

    ConsoleRegion(SHORT l, SHORT t, SHORT w, SHORT h, WORD attr) : left(l), top(t), width(w), height(h), attributes(attr)
    {
        buffer.resize(width * height);
    }

    void clear()
    {
        CHAR_INFO empty;
        empty.Char.AsciiChar = ' ';
        empty.Attributes     = attributes;
        std::fill(buffer.begin(), buffer.end(), empty);
    }
};

class window_mgr {
private:
    HANDLE hConsole;
    HANDLE hConsoleIn;

    ConsoleRegion top_bar;    // Status bar region
    ConsoleRegion top_win;    // Main message display region
    ConsoleRegion bottom_win; // Input region
    ConsoleRegion side_win;   // User list region

    input_wbuff input;
    int         status;
    int         focused_region;

    static void write_region(HANDLE hConsole, ConsoleRegion& region, const std::string& text, int row = 0)
    {
        COORD      bufferSize  = {region.width, region.height};
        COORD      bufferCoord = {0, 0};
        SMALL_RECT writeRegion = {region.left, static_cast<SHORT>(region.top + row), static_cast<SHORT>(region.left + region.width - 1),
                                  static_cast<SHORT>(region.top + region.height - 1)};

        for (size_t i = 0; i < text.length() && i < region.buffer.size(); i++) {
            region.buffer[i].Char.AsciiChar = text[i];
            region.buffer[i].Attributes     = region.attributes;
        }

        WriteConsoleOutput(hConsole, region.buffer.data(), bufferSize, bufferCoord, &writeRegion);
    }

    void scroll_region(ConsoleRegion& region, int lines)
    {
        if (lines == 0)
            return;

        if (lines > 0) {
            // Scroll up
            std::copy(region.buffer.begin() + lines * region.width, region.buffer.end(), region.buffer.begin());
        }
        else {
            // Scroll down
            std::copy_backward(region.buffer.begin(), region.buffer.end() + lines * region.width, region.buffer.end());
        }
    }

public:
    window_mgr() : status(0), focused_region(0)
    {
        hConsole   = GetStdHandle(STD_OUTPUT_HANDLE);
        hConsoleIn = GetStdHandle(STD_INPUT_HANDLE);
    }

    auto init() -> int 
    {
        if (status != 0)
            return W_ALREADY_INITED;

        // Get console window info
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
            return W_WINDOW_SIZE_INVALID;

        SHORT width  = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        SHORT height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;

        if (width < WIN_WIDTH_MIN || height < WIN_HEIGHT_MIN)
            return W_WINDOW_SIZE_INVALID;

        // Calculate region dimensions
        SHORT bottom_height = std::min(std::max(height / 3, BOTTOM_HEIGHT_MIN), BOTTOM_HEIGHT_MAX);
        SHORT side_width    = std::min(std::max(width / 4, SIDE_WIDTH_MIN), SIDE_WIDTH_MAX);

        // Initialize regions with appropriate colors
        top_bar = ConsoleRegion(0, 0, width, TOP_BAR_HEIGHT, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

        top_win = ConsoleRegion(0, TOP_BAR_HEIGHT + 1, width - side_width, height - bottom_height - TOP_BAR_HEIGHT - 1,
                                FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

        bottom_win = ConsoleRegion(0, height - bottom_height, width - side_width, bottom_height,
                                   FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

        side_win = ConsoleRegion(width - side_width, TOP_BAR_HEIGHT + 1, side_width, height - TOP_BAR_HEIGHT - 1,
                                 FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);

        // Clear all regions
        top_bar.clear();
        top_win.clear();
        bottom_win.clear();
        side_win.clear();

        // Enable window input mode
        DWORD mode;
        GetConsoleMode(hConsoleIn, &mode);
        mode |= ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT;
        SetConsoleMode(hConsoleIn, mode);

        status = 1;
        return W_NORMAL_RETURN;
    }

    auto set_win_color() -> int
    {
        if (status != 1)
            return W_NOT_INITIALIZED;

        // Check if colors are supported
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
            return W_COLOR_NOT_SUPPORTED;

        // Define colors for different regions using Windows console attributes
        // Windows colors are different from NCurses - we use combinations of RGB bits
        top_bar.attributes    = FOREGROUND_GREEN | FOREGROUND_INTENSITY;   // Bright green
        top_win.attributes    = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;    // Bright cyan
        bottom_win.attributes = FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;   // Bright yellow
        side_win.attributes   = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;        // Bright magenta

        // Clear and refresh each region with new colors
        top_bar.clear();
        top_win.clear();
        bottom_win.clear();
        side_win.clear();

        // Write initial content with new colors
        write_region(hConsole, top_bar, top_bar_msg);
        write_region(hConsole, top_win, welcome);
        write_region(hConsole, bottom_win, prompt);
        write_region(hConsole, side_win, "Users:\n");

        return W_NORMAL_RETURN;
    }

    int set()
    {
        if (status != 1)
            return W_NOT_INITIALIZED;

        // Write initial content
        write_region(hConsole, top_bar, top_bar_msg);
        write_region(hConsole, top_win, welcome);
        write_region(hConsole, bottom_win, prompt);
        write_region(hConsole, side_win, "Users:\n");

        status = 2;
        return W_NORMAL_RETURN;
    }

    bool close()
    {
        if (status != 3)
            return false;

        // Clear all regions before closing
        top_bar.clear();
        top_win.clear();
        bottom_win.clear();
        side_win.clear();

        // Reset console mode to original state
        SetConsoleMode(hConsoleIn, ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);

        // Close console handles
        if (hConsole != INVALID_HANDLE_VALUE) {
            CloseHandle(hConsole);
            hConsole = INVALID_HANDLE_VALUE;
        }

        if (hConsoleIn != INVALID_HANDLE_VALUE) {
            CloseHandle(hConsoleIn);
            hConsoleIn = INVALID_HANDLE_VALUE;
        }

        status = 0;
        return true;
    }

    void make_closable()
    {
        status = 3;
    }

    void force_close()
    {
        make_closable();
        close();
    }

    const auto get_status()
    {
        return status;
    }

    auto get_top_bar() -> const ConsoleRegion&
    {
        return top_bar;
    }

    auto get_top_win() -> const ConsoleRegion&
    {
        return top_win;
    }

    auto get_bottom_win() -> const ConsoleRegion&
    {
        return bottom_win;
    }

    auto get_side_win() -> const ConsoleRegion&
    {
        return side_win;
    }

    auto& get_input_wbuf()
    {
        return input;
    }

    std::string error_to_string(int ret)
    {
        switch (ret) {
        case W_NORMAL_RETURN: return "";
        case W_ALREADY_INITED: return "Windows console already initialized.";
        case W_COLOR_NOT_SUPPORTED: return "The terminal doesn't support color";
        case W_WINDOW_SIZE_INVALID:
            return "Window size too small (min: " + std::to_string(WIN_WIDTH_MIN) + " x " + std::to_string(WIN_HEIGHT_MIN) + ").";
        case W_WINDOW_CREATION_FAILED: return "Failed to create windows.";
        case W_NOT_INITIALIZED: return "Windows console not initialized.";
        default: return "Unknown error. Probably a bug triggered.";
        }
    }

    void clear_input(const std::string& prompt)
    {
        bottom_win.clear();
        write_region(hConsole, bottom_win, prompt);
    }

    bool refresh_input(const std::string& prompt, const input_wbuff& input)
    {
        std::string display =
            prompt + lc_strings::wstr_to_utf8(input.wstr) + " [" + std::to_string(input.wstr.size()) + "]  " + send_prompt;

        bottom_win.clear();
        write_region(hConsole, bottom_win, display);
        return true;
    }

    void switch_focused_region()
    {
        focused_region        = (focused_region + 1) % 4;
        std::string regions[] = {"top_bar", "msg_win", "input_win", "side_win"};
        std::string title     = top_bar_msg + "  (focused: " + regions[focused_region] + ")";
        write_region(hConsole, top_bar, title);
    }

    auto get_focused_win() -> ConsoleRegion*
    {
        switch (focused_region) {
        case 0: return &top_bar;
        case 1: return &top_win;
        case 2: return &bottom_win;
        case 3: return &side_win;
        default: return nullptr;
        }
    }

    int fmt_prnt_msg(const std::string& utf8_msg, const std::string& uname)
    {
        if (utf8_msg.empty())
            return 1;

        auto parsed_msg = lc_utils::split_buffer(reinterpret_cast<const uint8_t*>(utf8_msg.data()), utf8_msg.size(), ',', 3);

        if (parsed_msg.size() < 3)
            return 3;

        std::string timestamp = parsed_msg[0];
        std::string msg_uname = parsed_msg[1];
        std::string msg_body  = utf8_msg.substr(parsed_msg[0].size() + 1 + parsed_msg[1].size() + 1);

        std::string formatted;
        if (msg_uname == uname) {
            formatted = "[YOU] " + uname + ": " + timestamp + "\n" + msg_body + "\n";
        }
        else {
            formatted = msg_uname + ": " + timestamp + "\n" + msg_body + "\n";
        }

        // Append to top_win buffer and scroll if needed
        write_region(hConsole, top_win, formatted, top_win.height - 2);
        scroll_region(top_win, 2);

        return 0;
    }

    void welcome_user(const std::string& uemail, const std::string& uname)
    {
        std::string msg = "\n[SYSTEM] Your unique email: " + uemail + "\n" + "[SYSTEM] Your unique username: " + uname + "\n\n";
        write_region(hConsole, top_win, msg);
    }

    void wprint_to_output(const std::string& msg)
    {
        // Find first empty line in top_win buffer or use last line
        int write_row = 0;
        for (int i = 0; i < top_win.height; i++) {
            if (top_win.buffer[i * top_win.width].Char.AsciiChar == ' ') {
                write_row = i;
                break;
            }
            if (i == top_win.height - 1) {
                // If no empty line found, scroll up one line
                scroll_region(top_win, 1);
                write_row = top_win.height - 1;
            }
        }

        write_region(hConsole, top_win, msg, write_row);
    }

    void wprint_user_list(const std::string& ulist_str)
    {
        write_region(hConsole, side_win, ulist_str);
    }

    static void wprint_array(HANDLE hConsole, ConsoleRegion* region, const uint8_t* arr, const size_t n)
    {
        std::ostringstream oss;
        oss << "\n";
        for (size_t i = 0; i < n; ++i) { oss << std::hex << static_cast<int>(arr[i]) << " "; }
        oss << "\n";

        // If region is valid, write to it
        if (region) {
            std::string output = oss.str();
            write_region(hConsole, *region, output);
        }
    }

    int winput()
    {
        INPUT_RECORD inputRecord;
        DWORD        numEventsRead;
        bool         shift_pressed = false;

        while (!heartbeat_timeout && !auto_signout) {
            ReadConsoleInput(hConsoleIn, &inputRecord, 1, &numEventsRead);

            if (inputRecord.EventType == KEY_EVENT && inputRecord.Event.KeyEvent.bKeyDown) {
                // Track shift key state
                if (inputRecord.Event.KeyEvent.wVirtualKeyCode == VK_SHIFT) {
                    shift_pressed = true;
                    continue;
                }

                // Handle special keys
                if (inputRecord.Event.KeyEvent.wVirtualKeyCode == VK_END && shift_pressed) {
                    // Handle send message (Shift+End)
                    if (input.bytes == 0)
                        continue;

                    if (input.wstr == L":q!") {
                        send_gby_req.store(true);
                        return 0;
                    }

                    mtx.lock();
                    send_msg_body = lc_strings::wstr_to_utf8(input.wstr);
                    mtx.unlock();
                    send_msg_req.store(true);
                    input.wstr = L"";
                    clear_input(prompt);
                    continue;
                }

                if (inputRecord.Event.KeyEvent.wVirtualKeyCode == VK_BACK) {
                    if (input.bytes > 0) {
                        input.wstr.pop_back();
                        refresh_input(prompt, input);
                    }
                    continue;
                }

                // Handle regular character input
                wchar_t ch = inputRecord.Event.KeyEvent.uChar.UnicodeChar;
                if (ch == 0)
                    continue; // Skip non-character keys

                if (ch == L'\t') {
                    input.wstr += L"    ";
                }
                else if (iswprint(ch) || ch == '\n' || ch == '\r') {
                    input.wstr.push_back(ch);
                }

                input.bytes = lc_strings::get_wstr_utf8_bytes(input.wstr);
                if (input.bytes >= INPUT_BUFF_BYTES - 1) {
                    // Buffer full, trigger send
                    mtx.lock();
                    send_msg_body = lc_strings::wstr_to_utf8(input.wstr);
                    mtx.unlock();
                    send_msg_req.store(true);
                    input.wstr = L"";
                    clear_input(prompt);
                    continue;
                }

                refresh_input(prompt, input);
            }
            else if (inputRecord.EventType == KEY_EVENT && !inputRecord.Event.KeyEvent.bKeyDown) {
                // Handle key release
                if (inputRecord.Event.KeyEvent.wVirtualKeyCode == VK_SHIFT) {
                    shift_pressed = false;
                }
            }
        }
        return 1;
    }
};

    // Clean up