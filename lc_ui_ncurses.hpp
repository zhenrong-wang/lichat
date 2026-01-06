/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#ifndef LC_UI_NCURSES_HPP
#define LC_UI_NCURSES_HPP

#include "lc_ui_interface.hpp"
#include "lc_winmgr.hpp"
#include "lc_strings.hpp"
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <sstream>

namespace lichat {

/**
 * ncurses-based UI implementation
 * 
 * This adapter wraps the existing window_mgr to implement the ui_interface,
 * allowing the core to work with the abstract interface while keeping
 * the existing ncurses UI functional.
 */
class ncurses_ui : public ui_interface {
private:
    window_mgr winmgr_;
    std::queue<std::string> input_queue_;
    std::mutex input_mutex_;
    std::atomic<bool> should_exit_;
    std::atomic<bool> disconnect_requested_;
    std::string current_username_;
    std::thread input_thread_;
    std::atomic<bool> input_thread_running_;
    
    // Helper to parse user list string into vector
    std::vector<user_list_entry> parse_user_list(const std::string& user_list_str) {
        std::vector<user_list_entry> users;
        std::istringstream iss(user_list_str);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.empty()) continue;
            user_list_entry entry;
            // Check if user has "(in)" suffix
            size_t in_pos = line.find(" (in)");
            if (in_pos != std::string::npos) {
                entry.username = line.substr(0, in_pos);
                entry.is_online = true;
            } else {
                entry.username = line;
                entry.is_online = false;
            }
            users.push_back(entry);
        }
        return users;
    }
    
    // Input thread function
    void input_thread_func() {
        while (input_thread_running_) {
            // Check for input (non-blocking)
            // The window_mgr's winput() is blocking, so we need a different approach
            // For now, we'll use a polling mechanism
            // TODO: Make window_mgr support non-blocking input
            
            // Small sleep to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

public:
    ncurses_ui() 
        : should_exit_(false), 
          disconnect_requested_(false),
          input_thread_running_(false) {
    }
    
    ~ncurses_ui() {
        shutdown();
    }
    
    int init() override {
        auto ret = winmgr_.init();
        if (ret != W_NORMAL_RETURN) {
            return ret;
        }
        winmgr_.set();
        should_exit_ = false;
        disconnect_requested_ = false;
        input_thread_running_ = true;
        input_thread_ = std::thread(&ncurses_ui::input_thread_func, this);
        return 0;
    }
    
    void shutdown() override {
        input_thread_running_ = false;
        if (input_thread_.joinable()) {
            input_thread_.join();
        }
        winmgr_.force_close();
    }
    
    void on_user_authenticated(const user_info& user) override {
        current_username_ = user.username;
        winmgr_.welcome_user(user.email, user.username);
    }
    
    void on_user_disconnected() override {
        // UI can show disconnect message if needed
    }
    
    void on_message_received(const chat_message& msg) override {
        if (msg.is_system) {
            winmgr_.fmt_prnt_msg("[SYSTEM]", msg.timestamp, msg.content, 
                                current_username_);
        } else {
            winmgr_.fmt_prnt_msg(msg.from_user, msg.timestamp, msg.content,
                                current_username_);
        }
    }
    
    void on_user_list_updated(const std::vector<user_list_entry>& users) override {
        std::string user_list_str = "Users:\n";
        for (const auto& u : users) {
            user_list_str += u.username;
            if (u.is_online) {
                user_list_str += " (in)";
            }
            user_list_str += "\n";
        }
        winmgr_.wprint_user_list(user_list_str);
    }
    
    void on_error(const std::string& error_msg) override {
        winmgr_.wprint_to_output(error_msg);
    }
    
    void on_status_changed(const std::string& status) override {
        // Can show status in UI if needed
        winmgr_.wprint_to_output("[STATUS] " + status + "\n");
    }
    
    void on_heartbeat_timeout() override {
        winmgr_.wprint_to_output("\nHeartbeat failed. Press any key to exit.\n");
        should_exit_ = true;
    }
    
    bool has_input() override {
        std::lock_guard<std::mutex> lock(input_mutex_);
        return !input_queue_.empty();
    }
    
    std::string get_input() override {
        std::lock_guard<std::mutex> lock(input_mutex_);
        if (input_queue_.empty()) {
            return "";
        }
        std::string input = input_queue_.front();
        input_queue_.pop();
        return input;
    }
    
    void clear_input() override {
        std::lock_guard<std::mutex> lock(input_mutex_);
        while (!input_queue_.empty()) {
            input_queue_.pop();
        }
    }
    
    bool should_exit() override {
        return should_exit_;
    }
    
    void request_disconnect() override {
        disconnect_requested_ = true;
    }
    
    bool is_disconnect_requested() override {
        return disconnect_requested_;
    }
    
    void clear_disconnect_request() override {
        disconnect_requested_ = false;
    }
    
    // Get underlying window_mgr for legacy compatibility
    window_mgr& get_window_mgr() {
        return winmgr_;
    }
    
    // Method to queue input (called from window_mgr when input is received)
    void queue_input(const std::string& input) {
        std::lock_guard<std::mutex> lock(input_mutex_);
        input_queue_.push(input);
    }
    
    // Check if should exit (for window_mgr integration)
    bool get_should_exit() const {
        return should_exit_;
    }
};

} // namespace lichat

#endif // LC_UI_NCURSES_HPP

