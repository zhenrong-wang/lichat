/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#ifndef LC_UI_QT_HPP
#define LC_UI_QT_HPP

#include "lc_ui_interface.hpp"
#include <QMainWindow>
#include <QWidget>
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QListWidget>
#include <QLabel>
#include <QDialogButtonBox>
#include <QThread>
#include <QQueue>
#include <QMutex>
#include <QWaitCondition>
#include <QTimer>
#include <memory>
#include <atomic>

namespace lichat {

/**
 * Qt-based UI implementation for LiChat client
 * 
 * This provides a modern, cross-platform GUI using Qt.
 * The UI runs in the main thread and communicates with the core
 * via the ui_interface.
 */
// Forward declaration for signal/slot communication
class qt_ui_worker;

class qt_ui : public QMainWindow, public ui_interface {
    Q_OBJECT

private:
    // UI Components
    QWidget* central_widget_;
    QVBoxLayout* main_layout_;
    QHBoxLayout* content_layout_;
    
    QTextEdit* chat_display_;      // Message display area
    QListWidget* user_list_;       // User list sidebar
    QLineEdit* input_field_;       // Message input
    QPushButton* send_button_;     // Send button
    QLabel* status_label_;         // Status bar
    
    // Server configuration dialog
    QDialog* server_config_dialog_;
    QLineEdit* server_address_field_;
    QLineEdit* server_port_field_;
    QPushButton* server_config_ok_button_;
    QPushButton* server_config_cancel_button_;
    QLabel* server_config_error_label_;
    bool server_config_cancelled_;
    bool server_config_ready_;
    QMutex server_config_mutex_;
    QWaitCondition server_config_condition_;
    
    // Authentication choice dialog
    QDialog* auth_choice_dialog_;  // Choice between signup/signin
    QPushButton* choice_signup_button_;
    QPushButton* choice_signin_button_;
    
    // Authentication dialog
    QDialog* auth_dialog_;         // Login/signup dialog
    QLineEdit* auth_email_field_;
    QLineEdit* auth_username_field_;
    QLineEdit* auth_password_field_;
    QLineEdit* auth_password_confirm_field_;
    QPushButton* auth_submit_button_;
    QPushButton* auth_cancel_button_;
    QLabel* auth_error_label_;
    bool auth_cancelled_;
    bool auth_credentials_ready_;
    bool auth_is_signup_;
    QMutex auth_mutex_;
    QWaitCondition auth_condition_;
    
    // State
    std::atomic<bool> should_exit_;
    std::atomic<bool> disconnect_requested_;
    QQueue<QString> input_queue_;
    QMutex input_mutex_;
    QString current_username_;
    
    // Thread-safe event queues (core thread -> main thread)
    struct ui_event {
        enum type { MESSAGE, USER_LIST, ERROR, STATUS, AUTH } event_type;
        chat_message msg;
        std::vector<user_list_entry> users;
        std::string error_str;
        std::string status_str;
        user_info user_info_data;
    };
    QQueue<ui_event> event_queue_;
    QMutex event_mutex_;
    QTimer* event_timer_;  // Timer to process events in main thread
    
    // Helper methods
    void setup_ui();
    void setup_connections();
    void setup_server_config_dialog();
    void setup_auth_choice_dialog();
    void setup_auth_dialog();
    QString format_message(const chat_message& msg);
    void update_user_list_display(const std::vector<user_list_entry>& users);
    void process_events();  // Process queued events (called from main thread)
    
    // Auth dialog slots
    void on_auth_submit();
    void on_auth_cancel();
    void on_auth_fields_changed();
    
    // Choice dialog slots
    void on_choice_signup();
    void on_choice_signin();
    
    // Server config dialog slots
    void on_server_config_ok();
    void on_server_config_cancel();
    
    // Internal method to show server config dialog (called from main thread via invokeMethod)
    Q_INVOKABLE void show_server_config_dialog_internal();
    
    // Internal method to show choice dialog (called from main thread via invokeMethod)
    Q_INVOKABLE void show_auth_choice_dialog_internal();
    
    // Internal method to show auth dialog (called from main thread via invokeMethod)
    Q_INVOKABLE void show_auth_dialog_internal(bool is_signup);

private slots:
    void on_send_clicked();
    void on_input_return_pressed();
    void on_disconnect_clicked();
    
    // Thread-safe slots (called via queued connections)
    void handle_message_received(const chat_message& msg);
    void handle_user_list_updated(const std::vector<user_list_entry>& users);
    void handle_error(const QString& error_msg);
    void handle_status_changed(const QString& status);
    void handle_user_authenticated(const user_info& user);

public:
    explicit qt_ui(QWidget* parent = nullptr);
    ~qt_ui() override;

    // ui_interface implementation
    int init() override;
    void shutdown() override;
    
    void on_user_authenticated(const user_info& user) override;
    void on_user_disconnected() override;
    
    void on_message_received(const chat_message& msg) override;
    void on_user_list_updated(const std::vector<user_list_entry>& users) override;
    
    void on_error(const std::string& error_msg) override;
    void on_status_changed(const std::string& status) override;
    void on_heartbeat_timeout() override;
    
    bool request_server_config(std::string& server_address, 
                               std::string& server_port) override;
    
    bool request_auth_credentials(bool& is_signup, 
                                  std::string& email, 
                                  std::string& username, 
                                  std::string& password) override;
    
    bool has_input() override;
    std::string get_input() override;
    void clear_input() override;
    
    bool should_exit() override;
    void request_disconnect() override;
    bool is_disconnect_requested() override;
    void clear_disconnect_request() override;
};

} // namespace lichat

#endif // LC_UI_QT_HPP

