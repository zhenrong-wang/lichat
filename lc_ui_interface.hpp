/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#ifndef LC_UI_INTERFACE_HPP
#define LC_UI_INTERFACE_HPP

#include <string>
#include <vector>
#include <memory>

namespace lichat {

// Forward declarations
struct user_info {
    std::string email;
    std::string username;
    
    user_info() = default;
    user_info(const std::string& e, const std::string& n) 
        : email(e), username(n) {}
};

struct chat_message {
    std::string from_user;      // Sender username or "[SYSTEM]"
    std::string timestamp;      // Message timestamp
    std::string content;         // Message content
    bool is_system;             // True if system message
    bool is_from_me;            // True if message is from current user
    
    chat_message() : is_system(false), is_from_me(false) {}
};

struct user_list_entry {
    std::string username;
    bool is_online;
    
    user_list_entry() : is_online(false) {}
    user_list_entry(const std::string& name, bool online) 
        : username(name), is_online(online) {}
};

/**
 * Abstract UI interface for LiChat client
 * 
 * This interface decouples the client core from specific UI implementations.
 * Any UI (ncurses, Qt, web, etc.) can implement this interface.
 * 
 * Thread safety: All methods should be thread-safe as they may be called
 * from the core network thread.
 */
class ui_interface {
public:
    virtual ~ui_interface() = default;
    
    // ========== Initialization & Lifecycle ==========
    
    /**
     * Initialize the UI
     * @return 0 on success, error code on failure
     */
    virtual int init() = 0;
    
    /**
     * Shutdown and cleanup UI resources
     */
    virtual void shutdown() = 0;
    
    // ========== User Events ==========
    
    /**
     * Called when user successfully authenticates
     * @param user User information (email, username)
     */
    virtual void on_user_authenticated(const user_info& user) = 0;
    
    /**
     * Called when user disconnects or signs out
     */
    virtual void on_user_disconnected() = 0;
    
    // ========== Message Events ==========
    
    /**
     * Called when a chat message is received
     * @param msg The received message
     */
    virtual void on_message_received(const chat_message& msg) = 0;
    
    /**
     * Called when the user list is updated
     * @param users List of users with their online status
     */
    virtual void on_user_list_updated(const std::vector<user_list_entry>& users) = 0;
    
    // ========== Status & Error Events ==========
    
    /**
     * Called when an error occurs
     * @param error_msg Error message to display
     */
    virtual void on_error(const std::string& error_msg) = 0;
    
    /**
     * Called when status changes (e.g., connecting, connected, disconnected)
     * @param status Status message
     */
    virtual void on_status_changed(const std::string& status) = 0;
    
    /**
     * Called when heartbeat times out (connection lost)
     */
    virtual void on_heartbeat_timeout() = 0;
    
    // ========== Server Configuration ==========
    
    /**
     * Request server connection configuration from user
     * This should block until user provides server info or cancels
     * @param server_address Output: server address or hostname
     * @param server_port Output: server port
     * @return true if server info provided, false if cancelled
     */
    virtual bool request_server_config(std::string& server_address, 
                                      std::string& server_port) = 0;
    
    // ========== Authentication ==========
    
    /**
     * Request authentication credentials from user
     * This should block until user provides credentials or cancels
     * @param is_signup Input: ignored (user chooses in UI). Output: true if signup was chosen
     * @param email Output: user email (empty if login by username)
     * @param username Output: username
     * @param password Output: password
     * @return true if credentials provided, false if cancelled
     */
    virtual bool request_auth_credentials(bool& is_signup, 
                                         std::string& email, 
                                         std::string& username, 
                                         std::string& password) = 0;
    
    // ========== Input Handling ==========
    
    /**
     * Check if there is user input available
     * This should be non-blocking
     * @return true if input is available
     */
    virtual bool has_input() = 0;
    
    /**
     * Get user input if available
     * This should be non-blocking
     * @return Input string, or empty string if no input
     */
    virtual std::string get_input() = 0;
    
    /**
     * Clear any pending input
     */
    virtual void clear_input() = 0;
    
    // ========== Control ==========
    
    /**
     * Check if UI wants to exit
     * @return true if exit requested
     */
    virtual bool should_exit() = 0;
    
    /**
     * Request disconnect from server
     * Called when user wants to sign out
     */
    virtual void request_disconnect() = 0;
    
    /**
     * Check if disconnect was requested
     * @return true if disconnect requested
     */
    virtual bool is_disconnect_requested() = 0;
    
    /**
     * Reset disconnect request flag
     */
    virtual void clear_disconnect_request() = 0;
};

} // namespace lichat

#endif // LC_UI_INTERFACE_HPP

