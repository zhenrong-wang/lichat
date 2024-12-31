/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#ifndef LC_WINMGR_HPP
#define LC_WINMGR_HPP

#include "lc_consts.hpp"
#include "lc_strings.hpp"
#include "lc_common.hpp"
#include <string>
#include <cstring>
#include <sstream>
#include <ncurses.h>
#include <array>
#include <vector>
#include <mutex>
#include <atomic>

constexpr int WIN_HEIGHT_MIN = 16;
constexpr int WIN_WIDTH_MIN = 52;

constexpr int TOP_BAR_HEIGHT = 1;
constexpr int BOTTOM_HEIGHT_MIN = 6;
constexpr int BOTTOM_HEIGHT_MAX = 12;
constexpr int SIDE_WIDTH_MIN = ULOGIN_MIN_BYTES + 8;
constexpr int SIDE_WIDTH_MAX = UNAME_MAX_BYTES + 8;

constexpr char welcome[] = "Welcome to LightChat Service (aka LiChat)!\n\
We support Free Software and Free Speech.\n\
Code: https://github.com/zhenrong-wang/lichat\n";

const std::string prompt = "Input: ";
const std::string send_prompt = "([SHIFT][END] to send)";
const std::string top_bar_msg = 
    "LiChat: Free Software (LIC: MIT) for Free Speech.";

/* These external variables should be defined in the client core code. */
extern std::atomic<bool> send_msg_req;
extern std::atomic<bool> send_gby_req;
extern std::string send_msg_body;
extern std::mutex mtx;
extern std::atomic<bool> auto_signout;
extern std::atomic<bool> heartbeat_timeout;

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
    size_t bytes;
    input_wbuff () : wstr(L""), bytes(0) {};
};

struct point {
    int y;
    int x;
    point () : y(0), x(0) {}
    point (int y_in, int x_in) : y(y_in), x(x_in) {}
};

struct rect {
    struct point p0;
    struct point p1;
    rect () : p0(point()), p1(point()) {}
};

class window_mgr {
    WINDOW *top_bar;    // 0
    WINDOW *top_win;    // 1
    WINDOW *bottom_win; // 2
    WINDOW *side_win;   // 3
    std::array<struct rect, 4> rects;
    WINDOW *focused_win;
    input_wbuff input;
    int status;     // 0 - not initialized
                    // 1 - created
                    // 2 - set, ready for use, active
                    // 3 - closable/collectable

public: 
    window_mgr () : top_bar(nullptr), top_win(nullptr), bottom_win(nullptr),
        side_win(nullptr), focused_win(nullptr), input(input_wbuff()),
        status(0) {};

    int init () {
        if (status != 0) 
            return W_ALREADY_INITED;
        // Now start initialization.
        setlocale(LC_ALL, "");
        initscr();
        cbreak();
        noecho();

        int height = 0, width = 0;
        getmaxyx(stdscr, height, width);
        if (width < WIN_WIDTH_MIN || height < WIN_HEIGHT_MIN) {
            endwin();
            return W_WINDOW_SIZE_INVALID;
        }
        
        int bottom_height = ((height / 3) < BOTTOM_HEIGHT_MIN) ? 
                            BOTTOM_HEIGHT_MIN : 
                            (((height / 3) > BOTTOM_HEIGHT_MAX) ? 
                            BOTTOM_HEIGHT_MAX : (height / 3));

        int side_win_width = ((width / 4) < SIDE_WIDTH_MIN) ?
                             SIDE_WIDTH_MIN :
                             (((width / 4) > SIDE_WIDTH_MAX) ?
                             SIDE_WIDTH_MAX : (width / 4));

        top_bar = newwin(TOP_BAR_HEIGHT, width - 2, 1, 1);
        top_win = newwin(height - bottom_height - TOP_BAR_HEIGHT - 4, 
                         width - side_win_width - 3, TOP_BAR_HEIGHT + 2, 1);
        bottom_win = newwin(bottom_height, width - side_win_width - 3, 
                            height - bottom_height - 1, 1);
        side_win = newwin(height - TOP_BAR_HEIGHT - 3, side_win_width, 
                          TOP_BAR_HEIGHT + 2, width - side_win_width - 1);
                          
        if (!top_bar || !top_win || !bottom_win || !side_win) {
            if (top_bar) delwin(top_bar);
            if (top_win) delwin(top_win);
            if (bottom_win) delwin(bottom_win);
            if (side_win) delwin(side_win);
            endwin();
            return W_WINDOW_CREATION_FAILED;
        }

        rects[0].p0 = {1, 1};
        rects[0].p1 = {2, width - 1};
        rects[1].p0 = {TOP_BAR_HEIGHT + 2, 1};
        rects[1].p1 = {height - bottom_height - 2, width - side_win_width - 2};
        rects[2].p0 = {height - bottom_height - 1, 1};
        rects[2].p1 = {height - 1, width - side_win_width - 2};
        rects[3].p0 = {TOP_BAR_HEIGHT + 2, width - side_win_width - 1};
        rects[3].p1 = {height - 1, width - 1};
        
        status = 1;
        return W_NORMAL_RETURN;
    }

    int set_win_color () {
        if (status != 1)
            return W_NOT_INITIALIZED;
        if (!has_colors())
            return W_COLOR_NOT_SUPPORTED;
        start_color();
        init_pair(1, COLOR_GREEN, COLOR_BLACK);     // top_bar
        init_pair(2, COLOR_CYAN, COLOR_BLACK);      // top_win
        init_pair(3, COLOR_YELLOW, COLOR_BLACK);    // bottom_win
        init_pair(4, COLOR_MAGENTA, COLOR_BLACK);   // side_win
        
        wbkgdset(top_bar, COLOR_PAIR(1));
        wbkgdset(top_win, COLOR_PAIR(2));
        wbkgdset(bottom_win, COLOR_PAIR(3));
        wbkgdset(side_win, COLOR_PAIR(4));

        wrefresh(top_bar);
        wrefresh(top_win);
        wrefresh(bottom_win);
        wrefresh(side_win);
        return W_NORMAL_RETURN;
    }

    int set () {
        if (status != 1) 
            return W_NOT_INITIALIZED;
        // activate keypad for input
        keypad(bottom_win, TRUE);
        // Activate scroll
        scrollok(top_bar, TRUE);
        scrollok(top_win, TRUE);
        scrollok(bottom_win, TRUE);
        scrollok(side_win, TRUE);
        auto set_color = set_win_color();
        wprintw(top_bar, top_bar_msg.c_str());
        wrefresh(top_bar);
        if (set_color != W_NORMAL_RETURN)
            wprintw(top_win, "%s\n[CLIENT]: Color not supported.\n", welcome);
        else
            wprintw(top_win, welcome);
        wrefresh(top_win);
        wprintw(bottom_win, prompt.c_str());
        wrefresh(bottom_win);
        wprintw(side_win, "Users: \n");
        wrefresh(side_win);
        return W_NORMAL_RETURN;
        status = 2;
    }
    // Thread risk! Please make sure the windows are not in use.
    bool close () {
        if (status != 3) 
            return false;
        delwin(top_bar);
        delwin(top_win);
        delwin(bottom_win);
        delwin(side_win);
        endwin();
        return true;
    }
    void make_closable () {
        status = 3;
    }
    void force_close () {
        make_closable();
        close();
    }
    const auto get_status () {
        return status;
    }
    auto get_top_bar () {
        return top_bar;
    }
    auto get_top_win () {
        return top_win;
    }
    auto get_bottom_win () {
        return bottom_win;
    }
    auto get_side_win () {
        return side_win;
    }
    auto& get_input_wbuf () {
        return input;
    }
    std::string error_to_string (int ret) {
        if (ret == W_NORMAL_RETURN)
            return "";
        if (ret == W_ALREADY_INITED)
            return "ncurses windows already initialized.";
        if (ret == W_COLOR_NOT_SUPPORTED)
            return "The terminal doesn't support color";
        if (ret == W_WINDOW_SIZE_INVALID) {
            std::ostringstream oss;
            oss << "Window size too small (min: w x h " 
                << (int)WIN_WIDTH_MIN << " x " << (int)WIN_HEIGHT_MIN << " ).";
            return oss.str();
        }
        if (ret == W_WINDOW_CREATION_FAILED) 
            return "Failed to create windows.";
        if (ret == W_NOT_INITIALIZED) 
            return "ncurses windows not initialized.";
        else 
            return "Unknown error. Probably a bug triggered.";
    }

    void clear_input(const std::string& prompt) {
        if (bottom_win == nullptr) 
            return;
        int w = getmaxx(bottom_win);
        if (w <= 0) 
            return;
        //int start_y = prompt.size() / w, start_x = prompt.size() % w;
        mvwprintw(bottom_win, 0, 0, prompt.c_str());
        //wmove(bottom_win, start_y, start_x);
        wclrtobot(bottom_win);
        wrefresh(bottom_win);
    }

    bool refresh_input (const std::string& prompt, const input_wbuff& input) {
        if (bottom_win == nullptr) return false;
        int w = getmaxx(bottom_win);
        int start_y = prompt.size() / w, start_x = prompt.size() % w;
        wmove(bottom_win, start_y, start_x);
        wclrtobot(bottom_win);
        mvwprintw(bottom_win, start_y, start_x, "%s [%d]  %s", 
                  lc_strings::wstr_to_utf8(input.wstr).c_str(), 
                  input.wstr.size(), send_prompt.c_str());
        wrefresh(bottom_win);
        return true;
    }

    void switch_focused_win () {
        std::string win_name;
        if (focused_win == nullptr) {
            focused_win = top_bar;
            win_name = "  (focused: top_bar)";
        } 
        else if (focused_win == top_bar) {
            focused_win = top_win;
            win_name = "  (focused: msg_win)";
        } 
        else if (focused_win == top_win) {
            focused_win = bottom_win;
            win_name = "  (focused: input_win)";
        }
        else if (focused_win == bottom_win) {
            focused_win = side_win;
            win_name = "  (focused: side_win)";
        }  
        else {
            focused_win = nullptr;
            win_name = "  (focused: none)";
        }
        int top_bar_w = getmaxx(top_bar);
        std::string blank(top_bar_w, ' ');
        mvwprintw(top_bar, 0, 0, blank.c_str());
        mvwprintw(top_bar, 0, 0, "%s%s", top_bar_msg.c_str(), win_name.c_str());
        wrefresh(top_bar);
    }

    WINDOW *get_focused_win () {
        return focused_win;
    }

    // Every RAW message must start with at least:
    // timestamp,uname(or system), msg_body
    // Currenty this only handles narrow chars, not wide chars.

    static int fmt_for_print (std::string& utf8_out, const std::string& utf8_in, 
        const int col_start, const int col_end, const int win_width,
        const bool left_align) {
        if (utf8_in.empty())
            return -1;
        if (win_width <= 2 || col_start < 0 || col_end <= 0)
            return 1;
        if (col_end <= col_start || col_start >= win_width || col_end == 0)
            return 1;
        size_t line_len = static_cast<size_t>(col_end - col_start);
        size_t prefix_len = static_cast<size_t>(col_start); // Should be non-negative.
        size_t suffix_len = static_cast<size_t>(win_width - col_end); // Should be non-negative.
        std::string prefix(prefix_len, ' ');
        std::string suffix(suffix_len, ' ');

        auto ustr = icu::UnicodeString::fromUTF8(utf8_in);
        auto ustr_plen = lc_strings::get_ustr_print_len(ustr);

        auto is_single_line = [](const icu::UnicodeString& ustr, const size_t& len) {
            if (lc_strings::get_ustr_print_len(ustr) > len) 
                return false;
            for (int32_t i = 0; i < ustr.length(); ) {
                if (ustr.char32At(i) == '\r' || ustr.char32At(i) == '\n')
                    return false;
                i = ustr.moveIndex32(i, 1);
            }
            return true;
        };
        // Handle single line input.
        if (is_single_line(ustr, line_len)) {
            std::string padding(line_len - ustr_plen, ' ');
            if (left_align)
                utf8_out = prefix + utf8_in + padding + suffix;
            else 
                utf8_out = prefix + padding + utf8_in + suffix;
            return 0;
        }
        
        // Handle multiple line input.
        // All lines would be left aligned.
        struct split {
            size_t pos;
            int pdn;    // 0: nothing, 1: suffix, 2: 1 byte + suffix
            split (size_t p, int flag) : pos(p), pdn(flag) {}
        };
        utf8_out.clear();
        std::vector<struct split> splits;
        size_t len_tmp = 0;
        splits.push_back(split(0, 0));
        for (int32_t i = 0; i < ustr.length(); ) {
            if (ustr.char32At(i) == '\n' || ustr.char32At(i) == '\r') {
                splits.push_back(split(i + 1, 0));
                len_tmp = 0;
                i = ustr.moveIndex32(i, 1);
                continue;
            }
            auto char_pw = (!iswprint(ustr.char32At(i))) ? 0 : 
                            ((ustr.char32At(i) <= (UChar32)0x7FF) ? 1 : 2);
            if (len_tmp + char_pw > line_len) {
                if (len_tmp + char_pw - line_len == char_pw)
                    splits.push_back(split(i, 1));
                else 
                    splits.push_back(split(i, 2));
                len_tmp = char_pw;
            }
            else {
                len_tmp += char_pw;
            }
            i = ustr.moveIndex32(i, 1);
        }
        size_t idx = 0;
        while (idx < splits.size() - 1) {
            len_tmp = splits[idx + 1].pos - splits[idx].pos;
            auto u_substr = ustr.tempSubString(splits[idx].pos, len_tmp);
            std::string utf8_substr;
            u_substr.toUTF8String(utf8_substr);
            if (splits[idx + 1].pdn == 0) 
                utf8_out += (prefix + utf8_substr);
            else if (splits[idx + 1].pdn == 1) 
                utf8_out += (prefix + utf8_substr + suffix);
            else
                utf8_out += (prefix + utf8_substr + " " + suffix);
            ++ idx;
        }
        auto u_substr_last = ustr.tempSubString(splits[idx].pos, 
                                  ustr.length() - splits[idx].pos);
        auto u_substr_plen = lc_strings::get_ustr_print_len(u_substr_last);
        std::string padding(line_len - u_substr_plen, ' ');
        std::string utf8_substr_last;
        u_substr_last.toUTF8String(utf8_substr_last);
        utf8_out += prefix + utf8_substr_last + padding + suffix;
        return 0;
    }

    void wprint_user_list (const std::string& user_list) {
        mvwprintw(side_win, 0, 0, "Users:\n%s", user_list.c_str());
        wrefresh(side_win);
    }

    bool fmt_prnt_msg (const std::string& from_user, const std::string& timestamp,
        const std::string& bare_msg, const std::string& uname) {
        if (bare_msg.empty() || from_user.empty() || timestamp.empty())
            return false;

        int height = 0, width = 0, pos = 0;

        // Important: before running the tui, we have checked the width is >=
        // min_width, which is 48. So the top_win width should be at least 32.
        // So the self_col_start >= 16; other_col_end >= 24.
        // So the construction of std::string(size, char) should work because
        // the provided size are positive. Although without strict check.
        getmaxyx(top_win, height, width);
        int col_start, col_end;
        std::string fmt_name, fmt_timestmp, fmt_msg;
        bool left_align = true;

        if (from_user == uname) {
            col_start = (width < 2) ? 0 : (width / 2); // value >= 0
            col_end = width;
            left_align = false;
            fmt_for_print(fmt_name, std::string("[YOU] ") + uname + ":", 
                          col_start, col_end, width, left_align);
        }
        else {
            col_start = 0;
            col_end = (width * 3 / 4);
            fmt_for_print(fmt_name, from_user + ":", col_start, col_end, width, 
                          left_align);
        }
        fmt_for_print(fmt_timestmp, timestamp, col_start, col_end, width, 
                      left_align);
        fmt_for_print(fmt_msg, bare_msg, col_start, col_end, width, left_align);

        std::string fmt_lines = fmt_name + fmt_timestmp + fmt_msg;
        wprintw(top_win, "%s\n", fmt_lines.c_str());
        wrefresh(top_win);
        return true;
    }

    void welcome_user (const std::string& uemail, const std::string& uname) {
        wprintw(top_win, "\n[SYSTEM] Your unique email: %s\n", uemail.c_str()); 
        wprintw(top_win, "[SYSTEM] Your unique username: %s\n\n", uname.c_str()); 
        wrefresh(top_win);
    }

    void wprint_to_output (const std::string& msg) {
        wprintw(top_win, msg.c_str());
        wrefresh(top_win);
    }

    static void wprint_array(WINDOW *win, const uint8_t *arr, const size_t n) {
        wprintw(win, "\n");
        for (size_t i = 0; i < n; ++ i) 
            wprintw(win, "%x ", arr[i]);
        wprintw(win, "\n");
        wrefresh(win);
    }

    int winput () {
        wint_t wch = 0;
        while (!heartbeat_timeout && !auto_signout) {
            int res = wget_wch(bottom_win, &wch);
            input.bytes = lc_strings::get_wstr_utf8_bytes(input.wstr);
            auto input_done = false;
            if (res != OK) { // key input
                if (wch == KEY_BACKSPACE) {
                    if (input.bytes > 0)
                        input.wstr.pop_back();
                    refresh_input(prompt, input);
                    continue;
                }
                if (wch == KEY_SHOME) {
                    switch_focused_win();
                    continue;
                }
                // WIP: Scroll window is in progress.
                /*if (wch == KEY_UP) {
                    wscrl(winmgr.get_clicked_win(), 1);
                    wrefresh(winmgr.get_clicked_win());
                    continue;
                }
                if (wch == KEY_DOWN) {
                    wscrl(winmgr.get_clicked_win(), -1);
                    wrefresh(winmgr.get_clicked_win());
                    continue;
                }*/
                if (wch != KEY_SEND) 
                    continue;
                else 
                    input_done = true;
            }
            else {
                if (input.bytes == INPUT_BUFF_BYTES - 1)
                    input_done = true;
            }
            if (input_done) {
                if (input.bytes == 0) 
                    continue;
                if (input.wstr == L":q!") {
                    send_gby_req.store(true);
                    wget_wch(bottom_win, &wch);
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
            if (wch == L'\t') 
                input.wstr += L"    ";
            else if (iswprint(wch) || wch == '\n' || wch == '\r')
                input.wstr.push_back(wch);
            else 
                continue;
            refresh_input(prompt, input);
        }
        return 1;
    }
};

#endif