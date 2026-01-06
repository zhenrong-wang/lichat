/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#include "lc_ui_qt.hpp"
#include <QApplication>
#include <QThread>
#include <QMessageBox>
#include <QDateTime>
#include <QScrollBar>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QRegularExpressionValidator>
#include <QRegularExpression>
#include <QMetaObject>
#include <sstream>

namespace lichat {

qt_ui::qt_ui(QWidget* parent)
    : QMainWindow(parent),
      central_widget_(nullptr),
      main_layout_(nullptr),
      content_layout_(nullptr),
      chat_display_(nullptr),
      user_list_(nullptr),
      input_field_(nullptr),
      send_button_(nullptr),
      status_label_(nullptr),
      server_config_dialog_(nullptr),
      server_address_field_(nullptr),
      server_port_field_(nullptr),
      server_config_ok_button_(nullptr),
      server_config_cancel_button_(nullptr),
      server_config_error_label_(nullptr),
      server_config_cancelled_(false),
      server_config_ready_(false),
      auth_choice_dialog_(nullptr),
      choice_signup_button_(nullptr),
      choice_signin_button_(nullptr),
      auth_dialog_(nullptr),
      auth_email_field_(nullptr),
      auth_username_field_(nullptr),
      auth_password_field_(nullptr),
      auth_password_confirm_field_(nullptr),
      auth_submit_button_(nullptr),
      auth_cancel_button_(nullptr),
      auth_error_label_(nullptr),
      auth_cancelled_(false),
      auth_credentials_ready_(false),
      auth_is_signup_(false),
      event_timer_(nullptr) {
    
    setup_ui();
    setup_connections();
    setup_server_config_dialog();
    setup_auth_dialog();
    setup_auth_choice_dialog();
}

qt_ui::~qt_ui() {
    shutdown();
}

void qt_ui::setup_ui() {
    // Create central widget and main layout
    central_widget_ = new QWidget(this);
    setCentralWidget(central_widget_);
    main_layout_ = new QVBoxLayout(central_widget_);
    
    // Create content layout (chat + user list side by side)
    content_layout_ = new QHBoxLayout();
    
    // Chat display area
    chat_display_ = new QTextEdit(this);
    chat_display_->setReadOnly(true);
    chat_display_->setFont(QFont("Monospace", 10));
    content_layout_->addWidget(chat_display_, 3); // Takes 3/4 of space
    
    // User list sidebar
    user_list_ = new QListWidget(this);
    user_list_->setMaximumWidth(200);
    user_list_->setMinimumWidth(150);
    content_layout_->addWidget(user_list_, 1); // Takes 1/4 of space
    
    main_layout_->addLayout(content_layout_);
    
    // Input area (input field + send button)
    QHBoxLayout* input_layout = new QHBoxLayout();
    input_field_ = new QLineEdit(this);
    input_field_->setPlaceholderText("Type your message here... (Press Enter to send)");
    send_button_ = new QPushButton("Send", this);
    input_layout->addWidget(input_field_, 1);
    input_layout->addWidget(send_button_);
    main_layout_->addLayout(input_layout);
    
    // Status bar
    status_label_ = new QLabel("Disconnected", this);
    status_label_->setStyleSheet("QLabel { background-color: #f0f0f0; padding: 5px; }");
    main_layout_->addWidget(status_label_);
    
    // Window properties
    setWindowTitle("LiChat - Secure Chat Client");
    resize(800, 600);
    setMinimumSize(600, 400);
}

void qt_ui::setup_connections() {
    connect(send_button_, &QPushButton::clicked, this, &qt_ui::on_send_clicked);
    connect(input_field_, &QLineEdit::returnPressed, this, &qt_ui::on_input_return_pressed);
    
    // Setup timer to process events from core thread
    event_timer_ = new QTimer(this);
    connect(event_timer_, &QTimer::timeout, this, &qt_ui::process_events);
    event_timer_->start(50);  // Check every 50ms
}

void qt_ui::setup_server_config_dialog() {
    server_config_dialog_ = new QDialog(this);
    server_config_dialog_->setWindowTitle("LiChat - Server Configuration");
    server_config_dialog_->setModal(true);
    server_config_dialog_->setMinimumWidth(400);
    
    QFormLayout* layout = new QFormLayout(server_config_dialog_);
    
    // Server address field
    server_address_field_ = new QLineEdit(server_config_dialog_);
    server_address_field_->setPlaceholderText("localhost or IP address");
    server_address_field_->setText("localhost");  // Default value
    layout->addRow("Server Address:", server_address_field_);
    
    // Server port field
    server_port_field_ = new QLineEdit(server_config_dialog_);
    server_port_field_->setPlaceholderText("8081");
    server_port_field_->setText("8081");  // Default value
    // Validate port number (1-65535)
    QRegularExpressionValidator* port_validator = 
        new QRegularExpressionValidator(QRegularExpression("^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"), 
                                        server_port_field_);
    server_port_field_->setValidator(port_validator);
    layout->addRow("Server Port:", server_port_field_);
    
    // Error label (initially hidden)
    server_config_error_label_ = new QLabel(server_config_dialog_);
    server_config_error_label_->setStyleSheet("QLabel { color: red; }");
    server_config_error_label_->setVisible(false);
    layout->addRow(server_config_error_label_);
    
    // Buttons
    QDialogButtonBox* button_box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, 
                                                         server_config_dialog_);
    server_config_ok_button_ = button_box->button(QDialogButtonBox::Ok);
    server_config_cancel_button_ = button_box->button(QDialogButtonBox::Cancel);
    layout->addRow(button_box);
    
    // Connect signals
    connect(server_config_ok_button_, &QPushButton::clicked, this, &qt_ui::on_server_config_ok);
    connect(server_config_cancel_button_, &QPushButton::clicked, this, &qt_ui::on_server_config_cancel);
    connect(server_config_dialog_, &QDialog::rejected, this, [this]() {
        QMutexLocker locker(&server_config_mutex_);
        server_config_cancelled_ = true;
        server_config_condition_.wakeAll();
    });
}

void qt_ui::setup_auth_choice_dialog() {
    auth_choice_dialog_ = new QDialog(this);
    auth_choice_dialog_->setWindowTitle("LiChat - Welcome");
    auth_choice_dialog_->setModal(true);
    auth_choice_dialog_->setMinimumWidth(300);
    auth_choice_dialog_->setMinimumHeight(150);
    
    QVBoxLayout* layout = new QVBoxLayout(auth_choice_dialog_);
    
    QLabel* welcome_label = new QLabel("Welcome to LiChat!\nPlease choose an option:", auth_choice_dialog_);
    welcome_label->setAlignment(Qt::AlignCenter);
    layout->addWidget(welcome_label);
    
    choice_signup_button_ = new QPushButton("Sign Up", auth_choice_dialog_);
    choice_signup_button_->setMinimumHeight(40);
    layout->addWidget(choice_signup_button_);
    
    choice_signin_button_ = new QPushButton("Sign In", auth_choice_dialog_);
    choice_signin_button_->setMinimumHeight(40);
    layout->addWidget(choice_signin_button_);
    
    // Connect signals
    connect(choice_signup_button_, &QPushButton::clicked, this, &qt_ui::on_choice_signup);
    connect(choice_signin_button_, &QPushButton::clicked, this, &qt_ui::on_choice_signin);
    
    // Handle window close/cancel
    connect(auth_choice_dialog_, &QDialog::rejected, this, [this]() {
        QMutexLocker locker(&auth_mutex_);
        auth_cancelled_ = true;
        auth_condition_.wakeAll();
    });
}

void qt_ui::setup_auth_dialog() {
    auth_dialog_ = new QDialog(this);
    auth_dialog_->setWindowTitle("LiChat - Authentication");
    auth_dialog_->setModal(true);
    auth_dialog_->setMinimumWidth(400);
    
    QFormLayout* layout = new QFormLayout(auth_dialog_);
    
    // Email field (for signup and email-based login)
    auth_email_field_ = new QLineEdit(auth_dialog_);
    auth_email_field_->setPlaceholderText("user@example.com");
    QRegularExpression email_regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    QRegularExpressionValidator* email_validator = new QRegularExpressionValidator(email_regex, auth_email_field_);
    auth_email_field_->setValidator(email_validator);
    layout->addRow("Email:", auth_email_field_);
    
    // Username field
    auth_username_field_ = new QLineEdit(auth_dialog_);
    auth_username_field_->setPlaceholderText("username");
    layout->addRow("Username:", auth_username_field_);
    
    // Password field
    auth_password_field_ = new QLineEdit(auth_dialog_);
    auth_password_field_->setEchoMode(QLineEdit::Password);
    auth_password_field_->setPlaceholderText("Enter password");
    layout->addRow("Password:", auth_password_field_);
    
    // Password confirm field (for signup only)
    auth_password_confirm_field_ = new QLineEdit(auth_dialog_);
    auth_password_confirm_field_->setEchoMode(QLineEdit::Password);
    auth_password_confirm_field_->setPlaceholderText("Confirm password");
    auth_password_confirm_field_->setVisible(false);  // Hidden by default
    layout->addRow("Confirm Password:", auth_password_confirm_field_);
    
    // Error label
    auth_error_label_ = new QLabel(auth_dialog_);
    auth_error_label_->setStyleSheet("QLabel { color: red; }");
    auth_error_label_->setWordWrap(true);
    auth_error_label_->setVisible(false);
    layout->addRow(auth_error_label_);
    
    // Buttons
    QDialogButtonBox* button_box = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, auth_dialog_);
    auth_submit_button_ = button_box->button(QDialogButtonBox::Ok);
    auth_submit_button_->setText("Sign In");
    auth_cancel_button_ = button_box->button(QDialogButtonBox::Cancel);
    layout->addRow(button_box);
    
    // Connect signals
    connect(auth_submit_button_, &QPushButton::clicked, this, &qt_ui::on_auth_submit);
    connect(auth_cancel_button_, &QPushButton::clicked, this, &qt_ui::on_auth_cancel);
    connect(auth_email_field_, &QLineEdit::textChanged, this, &qt_ui::on_auth_fields_changed);
    connect(auth_username_field_, &QLineEdit::textChanged, this, &qt_ui::on_auth_fields_changed);
    connect(auth_password_field_, &QLineEdit::textChanged, this, &qt_ui::on_auth_fields_changed);
    connect(auth_password_confirm_field_, &QLineEdit::textChanged, this, &qt_ui::on_auth_fields_changed);
    
    // Also connect returnPressed on password field to submit
    connect(auth_password_field_, &QLineEdit::returnPressed, this, &qt_ui::on_auth_submit);
    connect(auth_password_confirm_field_, &QLineEdit::returnPressed, this, &qt_ui::on_auth_submit);
}

int qt_ui::init() {
    // Qt UI is initialized in constructor
    // Just show the window
    show();
    return 0;
}

void qt_ui::shutdown() {
    // Qt will handle cleanup automatically
    close();
}

void qt_ui::on_user_authenticated(const user_info& user) {
    // Queue event from core thread
    QMutexLocker locker(&event_mutex_);
    ui_event evt;
    evt.event_type = ui_event::AUTH;
    evt.user_info_data = user;
    event_queue_.enqueue(evt);
}

void qt_ui::handle_user_authenticated(const user_info& user) {
    current_username_ = QString::fromStdString(user.username);
    QString welcome = QString("Welcome, %1 (%2)!")
                      .arg(QString::fromStdString(user.username))
                      .arg(QString::fromStdString(user.email));
    chat_display_->append(QString("<b style='color: green;'>[SYSTEM]</b> %1").arg(welcome));
    on_status_changed("Connected");
}

void qt_ui::on_user_disconnected() {
    chat_display_->append("<b style='color: red;'>[SYSTEM]</b> Disconnected from server.");
    on_status_changed("Disconnected");
}

QString qt_ui::format_message(const chat_message& msg) {
    QString timestamp = QString::fromStdString(msg.timestamp);
    QString content = QString::fromStdString(msg.content);
    QString from = QString::fromStdString(msg.from_user);
    
    QString formatted;
    if (msg.is_system) {
        formatted = QString("<b style='color: blue;'>[SYSTEM]</b> [%1] %2")
                    .arg(timestamp, content);
    } else if (msg.is_from_me) {
        formatted = QString("<div style='text-align: right; color: green;'>"
                           "<b>[YOU]</b> [%1]<br>%2</div>")
                    .arg(timestamp, content);
    } else {
        formatted = QString("<b style='color: purple;'>%1</b> [%2]<br>%3")
                    .arg(from, timestamp, content);
    }
    return formatted;
}

void qt_ui::on_message_received(const chat_message& msg) {
    // Queue event from core thread
    QMutexLocker locker(&event_mutex_);
    ui_event evt;
    evt.event_type = ui_event::MESSAGE;
    evt.msg = msg;
    event_queue_.enqueue(evt);
}

void qt_ui::handle_message_received(const chat_message& msg) {
    QString formatted = format_message(msg);
    chat_display_->append(formatted);
    
    // Auto-scroll to bottom
    QScrollBar* scrollbar = chat_display_->verticalScrollBar();
    scrollbar->setValue(scrollbar->maximum());
}

void qt_ui::update_user_list_display(const std::vector<user_list_entry>& users) {
    user_list_->clear();
    for (const auto& user : users) {
        QString username = QString::fromStdString(user.username);
        QString display = user.is_online 
            ? QString("%1 (online)").arg(username)
            : username;
        
        QListWidgetItem* item = new QListWidgetItem(display, user_list_);
        if (user.is_online) {
            item->setForeground(QBrush(QColor(0, 150, 0))); // Green for online
        } else {
            item->setForeground(QBrush(QColor(128, 128, 128))); // Gray for offline
        }
    }
}

void qt_ui::on_user_list_updated(const std::vector<user_list_entry>& users) {
    // Queue event from core thread
    QMutexLocker locker(&event_mutex_);
    ui_event evt;
    evt.event_type = ui_event::USER_LIST;
    evt.users = users;  // Copy the vector
    event_queue_.enqueue(evt);
}

void qt_ui::handle_user_list_updated(const std::vector<user_list_entry>& users) {
    update_user_list_display(users);
}

void qt_ui::on_error(const std::string& error_msg) {
    // Queue event from core thread
    QMutexLocker locker(&event_mutex_);
    ui_event evt;
    evt.event_type = ui_event::ERROR;
    evt.error_str = error_msg;
    event_queue_.enqueue(evt);
}

void qt_ui::handle_error(const QString& error_msg) {
    chat_display_->append(QString("<b style='color: red;'>[ERROR]</b> %1").arg(error_msg));
    QMessageBox::warning(this, "Error", error_msg);
}

void qt_ui::on_status_changed(const std::string& status) {
    // Queue event from core thread
    QMutexLocker locker(&event_mutex_);
    ui_event evt;
    evt.event_type = ui_event::STATUS;
    evt.status_str = status;
    event_queue_.enqueue(evt);
}

void qt_ui::handle_status_changed(const QString& status_text) {
    status_label_->setText(status_text);
    
    if (status_text.contains("Connected", Qt::CaseInsensitive)) {
        status_label_->setStyleSheet("QLabel { background-color: #90EE90; padding: 5px; }");
    } else if (status_text.contains("Disconnected", Qt::CaseInsensitive)) {
        status_label_->setStyleSheet("QLabel { background-color: #FFB6C1; padding: 5px; }");
    } else {
        status_label_->setStyleSheet("QLabel { background-color: #f0f0f0; padding: 5px; }");
    }
}

void qt_ui::process_events() {
    // Process events queued from core thread (runs in main thread)
    QMutexLocker locker(&event_mutex_);
    while (!event_queue_.empty()) {
        ui_event evt = event_queue_.dequeue();
        locker.unlock();  // Unlock while processing
        
        switch (evt.event_type) {
            case ui_event::MESSAGE:
                handle_message_received(evt.msg);
                break;
            case ui_event::USER_LIST:
                handle_user_list_updated(evt.users);
                break;
            case ui_event::ERROR:
                handle_error(QString::fromStdString(evt.error_str));
                break;
            case ui_event::STATUS:
                handle_status_changed(QString::fromStdString(evt.status_str));
                break;
            case ui_event::AUTH:
                handle_user_authenticated(evt.user_info_data);
                break;
        }
        
        locker.relock();  // Relock for next iteration
    }
}

void qt_ui::on_heartbeat_timeout() {
    on_error("Heartbeat timeout - connection lost");
    QMessageBox::critical(this, "Connection Lost", 
                         "Heartbeat timeout. Connection to server lost.\n"
                         "The application will close.");
    should_exit_ = true;
    close();
}

bool qt_ui::has_input() {
    QMutexLocker locker(&input_mutex_);
    return !input_queue_.empty();
}

std::string qt_ui::get_input() {
    QMutexLocker locker(&input_mutex_);
    if (input_queue_.empty()) {
        return "";
    }
    QString input = input_queue_.dequeue();
    return input.toStdString();
}

void qt_ui::clear_input() {
    QMutexLocker locker(&input_mutex_);
    input_queue_.clear();
}

bool qt_ui::should_exit() {
    return should_exit_;
}

void qt_ui::request_disconnect() {
    disconnect_requested_ = true;
}

bool qt_ui::is_disconnect_requested() {
    return disconnect_requested_;
}

void qt_ui::clear_disconnect_request() {
    disconnect_requested_ = false;
}

void qt_ui::on_send_clicked() {
    QString text = input_field_->text().trimmed();
    if (!text.isEmpty()) {
        QMutexLocker locker(&input_mutex_);
        input_queue_.enqueue(text);
        input_field_->clear();
    }
}

void qt_ui::on_input_return_pressed() {
    on_send_clicked();
}

void qt_ui::on_disconnect_clicked() {
    request_disconnect();
}

bool qt_ui::request_server_config(std::string& server_address, 
                                  std::string& server_port) {
    // This is called from main() before any threads start, so we can call directly
    // Initialize state
    {
        QMutexLocker locker(&server_config_mutex_);
        server_config_cancelled_ = false;
        server_config_ready_ = false;
    }
    
    // Show dialog directly (we're in the main thread)
    // We need to process events for the dialog to appear
    show_server_config_dialog_internal();
    
    // Wait for dialog to complete
    QMutexLocker locker(&server_config_mutex_);
    while (!server_config_ready_ && !server_config_cancelled_) {
        server_config_condition_.wait(&server_config_mutex_);
    }
    
    if (server_config_cancelled_) {
        return false;
    }
    
    if (!server_config_ready_) {
        return false;
    }
    
    // Get server config
    locker.unlock();  // Unlock before accessing Qt widgets
    server_address = server_address_field_->text().toStdString();
    server_port = server_port_field_->text().toStdString();
    
    return true;
}

bool qt_ui::request_auth_credentials(bool& is_signup, 
                                     std::string& email, 
                                     std::string& username, 
                                     std::string& password) {
    // This may be called from core thread, so we need to use Qt's invokeMethod
    // to show the dialog from the main thread
    
    // Initialize state
    {
        QMutexLocker locker(&auth_mutex_);
        auth_cancelled_ = false;
        auth_credentials_ready_ = false;
        auth_is_signup_ = false;  // Will be set by choice dialog
    }
    
    // First, show the choice dialog to let user pick signup or signin
    // Unlock mutex before blocking call to avoid deadlock
    QMetaObject::invokeMethod(this, "show_auth_choice_dialog_internal", 
                              Qt::BlockingQueuedConnection);
    
    // Wait for choice to be made (auth_credentials_ready_ is set when choice is made)
    QMutexLocker locker(&auth_mutex_);
    while (!auth_credentials_ready_ && !auth_cancelled_) {
        auth_condition_.wait(&auth_mutex_);
    }
    
    if (auth_cancelled_) {
        return false;
    }
    
    if (!auth_credentials_ready_) {
        return false;
    }
    
    // Store the choice and reset flag before unlocking
    bool signup_choice = auth_is_signup_;
    auth_credentials_ready_ = false;
    locker.unlock();
    
    // Show the auth dialog based on user's choice
    QMetaObject::invokeMethod(this, "show_auth_dialog_internal", 
                              Qt::BlockingQueuedConnection,
                              Q_ARG(bool, signup_choice));
    
    // Wait for auth dialog to complete
    QMutexLocker locker2(&auth_mutex_);
    while (!auth_credentials_ready_ && !auth_cancelled_) {
        auth_condition_.wait(&auth_mutex_);
    }
    
    if (auth_cancelled_) {
        return false;
    }
    
    if (!auth_credentials_ready_) {
        return false;
    }
    
    // Get credentials and signup flag
    is_signup = auth_is_signup_;
    locker2.unlock();  // Unlock before accessing Qt widgets (main thread)
    
    email = auth_email_field_->text().toStdString();
    username = auth_username_field_->text().toStdString();
    password = auth_password_field_->text().toStdString();
    
    return true;
}

void qt_ui::show_auth_dialog_internal(bool is_signup) {
    // This runs in the main thread
    auth_error_label_->setVisible(false);
    auth_error_label_->clear();
    
    // Configure dialog for signup or signin
    QFormLayout* form_layout = qobject_cast<QFormLayout*>(auth_dialog_->layout());
    if (is_signup) {
        auth_dialog_->setWindowTitle("LiChat - Sign Up");
        auth_submit_button_->setText("Sign Up");
        auth_email_field_->setVisible(true);
        auth_username_field_->setVisible(true);
        auth_password_confirm_field_->setVisible(true);
        if (form_layout) {
            QWidget* label_widget = form_layout->labelForField(auth_password_confirm_field_);
            if (label_widget) label_widget->setVisible(true);
        }
    } else {
        auth_dialog_->setWindowTitle("LiChat - Sign In");
        auth_submit_button_->setText("Sign In");
        auth_email_field_->setVisible(true);
        auth_username_field_->setVisible(true);
        auth_password_confirm_field_->setVisible(false);
        if (form_layout) {
            QWidget* label_widget = form_layout->labelForField(auth_password_confirm_field_);
            if (label_widget) label_widget->setVisible(false);
        }
    }
    
    // Clear fields
    auth_email_field_->clear();
    auth_username_field_->clear();
    auth_password_field_->clear();
    auth_password_confirm_field_->clear();
    
    // Show dialog (modal, blocks until closed)
    int result = auth_dialog_->exec();
    
    // Signal the waiting thread
    QMutexLocker locker(&auth_mutex_);
    if (result == QDialog::Rejected) {
        auth_cancelled_ = true;
    }
    auth_condition_.wakeAll();
}

void qt_ui::on_auth_submit() {
    QString email = auth_email_field_->text().trimmed();
    QString username = auth_username_field_->text().trimmed();
    QString password = auth_password_field_->text();
    QString password_confirm = auth_password_confirm_field_->text();
    
    // Basic validation
    bool is_signup = auth_password_confirm_field_->isVisible();
    
    if (is_signup) {
        // Signup validation
        if (email.isEmpty() || !auth_email_field_->hasAcceptableInput()) {
            auth_error_label_->setText("Please enter a valid email address.");
            auth_error_label_->setVisible(true);
            return;
        }
        if (username.isEmpty() || username.length() < 3) {
            auth_error_label_->setText("Username must be at least 3 characters.");
            auth_error_label_->setVisible(true);
            return;
        }
        if (password.length() < 8) {
            auth_error_label_->setText("Password must be at least 8 characters.");
            auth_error_label_->setVisible(true);
            return;
        }
        if (password != password_confirm) {
            auth_error_label_->setText("Passwords do not match.");
            auth_error_label_->setVisible(true);
            return;
        }
    } else {
        // Signin validation
        if (email.isEmpty() && username.isEmpty()) {
            auth_error_label_->setText("Please enter either email or username.");
            auth_error_label_->setVisible(true);
            return;
        }
        if (password.isEmpty()) {
            auth_error_label_->setText("Please enter your password.");
            auth_error_label_->setVisible(true);
            return;
        }
    }
    
    // Hide error and accept
    auth_error_label_->setVisible(false);
    QMutexLocker locker(&auth_mutex_);
    auth_credentials_ready_ = true;
    auth_dialog_->accept();
    auth_condition_.wakeAll();
}

void qt_ui::on_choice_signup() {
    QMutexLocker locker(&auth_mutex_);
    auth_is_signup_ = true;
    auth_credentials_ready_ = true;  // Signal that choice is made
    auth_choice_dialog_->accept();
    auth_condition_.wakeAll();
}

void qt_ui::on_choice_signin() {
    QMutexLocker locker(&auth_mutex_);
    auth_is_signup_ = false;
    auth_credentials_ready_ = true;  // Signal that choice is made
    auth_choice_dialog_->accept();
    auth_condition_.wakeAll();
}

void qt_ui::show_server_config_dialog_internal() {
    // This runs in the main thread
    server_config_error_label_->setVisible(false);
    server_config_error_label_->clear();
    
    // Show the main window first so dialogs have a parent
    show();
    
    // Process pending events to ensure UI is ready
    QApplication::processEvents();
    
    int result = server_config_dialog_->exec();
    
    // If dialog was closed/cancelled (not by button click)
    QMutexLocker locker(&server_config_mutex_);
    if (result == QDialog::Rejected && !server_config_ready_) {
        server_config_cancelled_ = true;
        server_config_condition_.wakeAll();
    }
}

void qt_ui::on_server_config_ok() {
    // Validate inputs
    QString address = server_address_field_->text().trimmed();
    QString port = server_port_field_->text().trimmed();
    
    if (address.isEmpty()) {
        server_config_error_label_->setText("Server address cannot be empty");
        server_config_error_label_->setVisible(true);
        return;
    }
    
    if (port.isEmpty()) {
        server_config_error_label_->setText("Server port cannot be empty");
        server_config_error_label_->setVisible(true);
        return;
    }
    
    bool port_ok;
    int port_num = port.toInt(&port_ok);
    if (!port_ok || port_num < 1 || port_num > 65535) {
        server_config_error_label_->setText("Invalid port number (must be 1-65535)");
        server_config_error_label_->setVisible(true);
        return;
    }
    
    // Hide error and accept
    server_config_error_label_->setVisible(false);
    QMutexLocker locker(&server_config_mutex_);
    server_config_ready_ = true;
    server_config_dialog_->accept();
    server_config_condition_.wakeAll();
}

void qt_ui::on_server_config_cancel() {
    QMutexLocker locker(&server_config_mutex_);
    server_config_cancelled_ = true;
    server_config_dialog_->reject();
    server_config_condition_.wakeAll();
}

void qt_ui::show_auth_choice_dialog_internal() {
    // This runs in the main thread
    int result = auth_choice_dialog_->exec();
    
    // If dialog was closed/cancelled (not by button click)
    QMutexLocker locker(&auth_mutex_);
    if (result == QDialog::Rejected && !auth_credentials_ready_) {
        auth_cancelled_ = true;
        auth_condition_.wakeAll();
    }
}

void qt_ui::on_auth_cancel() {
    QMutexLocker locker(&auth_mutex_);
    auth_cancelled_ = true;
    auth_dialog_->reject();
    auth_condition_.wakeAll();
}

void qt_ui::on_auth_fields_changed() {
    // Clear error when user starts typing
    if (auth_error_label_->isVisible()) {
        auth_error_label_->setVisible(false);
        auth_error_label_->clear();
    }
}

} // namespace lichat

