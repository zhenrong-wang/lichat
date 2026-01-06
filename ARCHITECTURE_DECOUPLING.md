# Architecture Decoupling: Client Core vs UI

## Current Architecture Analysis

### Problem: Tight Coupling

The current implementation has **tight coupling** between the client core (message processing) and the UI (ncurses). This creates several issues:

#### 1. **Direct UI Dependencies in Core**

The `thread_run_core` function directly calls UI methods:

```cpp
static void thread_run_core (window_mgr& w, ...) {
    w.welcome_user(u.get_uemail(), u.get_uname());        // Line 747
    w.wprint_to_output(heartbeat_timeout_msg);            // Line 751
    w.wprint_to_output(client_exit_msg);                  // Line 756
    w.wprint_to_output(signed_out_msg);                   // Line 767
    w.wprint_to_output(lmsg_recv_failed);                 // Lines 854, 858
    w.wprint_to_output(auto_signout_msg);                 // Line 961
    w.wprint_user_list(ulm.get_ulist());                  // Lines 967, 1001
    w.fmt_prnt_msg(...);                                  // Lines 1002, 1007
}
```

**Issues:**
- Core cannot run without UI
- Cannot test core logic independently
- Cannot swap UI implementations (GUI, web, CLI)
- Cannot run headless clients
- Violates Single Responsibility Principle

#### 2. **Global Shared State**

Communication between UI and core uses global variables:

```cpp
// Global state shared between UI and core
std::atomic<bool> send_msg_req(false);
std::atomic<bool> send_gby_req(false);
std::string send_msg_body;
std::mutex mtx;
std::atomic<bool> auto_signout(false);
std::atomic<bool> heartbeat_timeout(false);
```

**Issues:**
- Hidden dependencies
- Hard to reason about state
- Not thread-safe in all cases
- Difficult to test
- No clear ownership

#### 3. **UI-Specific Types in Core**

The core function signature requires `window_mgr&`, which is a concrete ncurses implementation:

```cpp
static void thread_run_core (window_mgr& w, ...)
```

**Issues:**
- Core depends on concrete UI implementation
- Cannot use different UI backends
- Hard to mock for testing

---

## Proposed Solution: Event-Driven Architecture

### Design Principles

1. **Separation of Concerns**: Core handles protocol, UI handles presentation
2. **Dependency Inversion**: Core depends on abstractions, not concrete UI
3. **Observer Pattern**: Core emits events, UI subscribes to events
4. **Message Queue**: Thread-safe communication channel

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    UI Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  ncurses_ui  │  │   gui_ui     │  │  headless_ui │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                 │                  │          │
│         └─────────────────┼──────────────────┘          │
│                           │                              │
│                  ┌────────▼────────┐                    │
│                  │  UI Interface   │                    │
│                  │  (Abstract)     │                    │
│                  └────────┬────────┘                    │
└───────────────────────────┼──────────────────────────────┘
                            │
                            │ Events / Callbacks
                            │
┌───────────────────────────▼──────────────────────────────┐
│              Client Core (Protocol Layer)                │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Message Processing                              │   │
│  │  - Network I/O                                   │   │
│  │  - Protocol handling                             │   │
│  │  - Encryption/Decryption                         │   │
│  │  - Session management                            │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Event Emitter                                   │   │
│  │  - on_message_received()                        │   │
│  │  - on_user_list_updated()                       │   │
│  │  - on_error()                                   │   │
│  │  - on_status_changed()                           │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Command Receiver                                │   │
│  │  - send_message()                                │   │
│  │  - disconnect()                                  │   │
│  └──────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
```

---

## Implementation Design

### Step 1: Define UI Interface (Abstract Base Class)

Create `lc_ui_interface.hpp`:

```cpp
#ifndef LC_UI_INTERFACE_HPP
#define LC_UI_INTERFACE_HPP

#include <string>
#include <vector>

// Forward declarations
struct user_info {
    std::string email;
    std::string username;
};

struct chat_message {
    std::string from_user;
    std::string timestamp;
    std::string content;
    bool is_system;
    bool is_from_me;
};

struct user_list_entry {
    std::string username;
    bool is_online;
};

// Abstract UI interface
class ui_interface {
public:
    virtual ~ui_interface() = default;
    
    // Initialization
    virtual int init() = 0;
    virtual void shutdown() = 0;
    
    // User events
    virtual void on_user_authenticated(const user_info& user) = 0;
    virtual void on_user_disconnected() = 0;
    
    // Message events
    virtual void on_message_received(const chat_message& msg) = 0;
    virtual void on_user_list_updated(const std::vector<user_list_entry>& users) = 0;
    
    // Status events
    virtual void on_error(const std::string& error_msg) = 0;
    virtual void on_status_changed(const std::string& status) = 0;
    virtual void on_heartbeat_timeout() = 0;
    
    // Input handling (non-blocking)
    virtual bool has_input() = 0;
    virtual std::string get_input() = 0;  // Returns empty if no input
    virtual void clear_input() = 0;
    
    // Control
    virtual bool should_exit() = 0;
    virtual void request_disconnect() = 0;
};

#endif
```

### Step 2: Create Event-Based Core

Refactor `thread_run_core` to use events instead of direct UI calls:

```cpp
class client_core {
private:
    ui_interface* ui_;  // Pointer to UI (not reference, allows nullptr)
    // ... other members ...
    
public:
    void set_ui(ui_interface* ui) {
        ui_ = ui;
    }
    
    void run_core_loop() {
        if (!ui_) {
            // Can run headless, just log errors
            return;
        }
        
        // Emit events instead of direct calls
        if (user_authenticated) {
            user_info info;
            info.email = user.get_uemail();
            info.username = user.get_uname();
            ui_->on_user_authenticated(info);
        }
        
        // Process messages
        while (core_running) {
            // ... network processing ...
            
            if (is_msg_recved) {
                chat_message msg;
                msg.from_user = parsed[0];
                msg.timestamp = parsed[1];
                msg.content = bare_msg;
                msg.is_system = (parsed[0] == "[S]");
                msg.is_from_me = (parsed[0] == user.get_uname());
                
                ui_->on_message_received(msg);
            }
            
            if (is_ulist_recved) {
                std::vector<user_list_entry> users;
                // ... populate users ...
                ui_->on_user_list_updated(users);
            }
            
            // Check for UI input
            if (ui_->has_input()) {
                std::string input = ui_->get_input();
                if (input == ":q!") {
                    ui_->request_disconnect();
                } else if (!input.empty()) {
                    send_message(input);
                }
            }
            
            // Check for disconnect request
            if (ui_->should_exit()) {
                send_goodbye();
                break;
            }
        }
    }
};
```

### Step 3: Implement ncurses UI Adapter

Create `lc_ui_ncurses.hpp` that implements `ui_interface`:

```cpp
#ifndef LC_UI_NCURSES_HPP
#define LC_UI_NCURSES_HPP

#include "lc_ui_interface.hpp"
#include "lc_winmgr.hpp"
#include <queue>
#include <mutex>

class ncurses_ui : public ui_interface {
private:
    window_mgr winmgr_;
    std::queue<std::string> input_queue_;
    std::mutex input_mutex_;
    bool should_exit_;
    bool disconnect_requested_;
    
public:
    int init() override {
        auto ret = winmgr_.init();
        if (ret != W_NORMAL_RETURN) {
            return ret;
        }
        winmgr_.set();
        should_exit_ = false;
        disconnect_requested_ = false;
        return 0;
    }
    
    void shutdown() override {
        winmgr_.force_close();
    }
    
    void on_user_authenticated(const user_info& user) override {
        winmgr_.welcome_user(user.email, user.username);
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
        std::string user_list_str;
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
    
    void on_heartbeat_timeout() override {
        winmgr_.wprint_to_output("\nHeartbeat failed. Press any key to exit.\n");
        should_exit_ = true;
    }
    
    bool has_input() override {
        // Non-blocking check
        return winmgr_.has_input_available();
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
    
    bool is_disconnect_requested() const {
        return disconnect_requested_;
    }
    
    // Separate input thread that feeds the queue
    void input_thread_loop() {
        while (!should_exit_) {
            std::string input = winmgr_.read_input_nonblocking();
            if (!input.empty()) {
                std::lock_guard<std::mutex> lock(input_mutex_);
                input_queue_.push(input);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
};

#endif
```

### Step 4: Refactor Main Client Code

```cpp
class lichat_client {
private:
    client_core core_;
    std::unique_ptr<ui_interface> ui_;
    
public:
    bool run_client() {
        // ... handshake code ...
        
        // Create UI (can be swapped for different implementations)
        ui_ = std::make_unique<ncurses_ui>();
        
        if (ui_->init() != 0) {
            return close_client(WINDOW_MGR_ERROR);
        }
        
        // Connect core to UI
        core_.set_ui(ui_.get());
        
        // Start threads
        std::thread core_thread([this]() {
            core_.run_core_loop();
        });
        
        std::thread input_thread([this]() {
            auto* ncurses = dynamic_cast<ncurses_ui*>(ui_.get());
            if (ncurses) {
                ncurses->input_thread_loop();
            }
        });
        
        // Wait for completion
        core_thread.join();
        input_thread.join();
        
        ui_->shutdown();
        return true;
    }
};
```

---

## Benefits of This Design

### 1. **Testability**
```cpp
// Mock UI for testing
class mock_ui : public ui_interface {
    std::vector<chat_message> received_messages_;
public:
    void on_message_received(const chat_message& msg) override {
        received_messages_.push_back(msg);
    }
    // ... other methods ...
};

// Test core without UI
TEST(ClientCore, MessageProcessing) {
    mock_ui ui;
    client_core core;
    core.set_ui(&ui);
    // ... test core logic ...
    ASSERT_EQ(ui.received_messages_.size(), 1);
}
```

### 2. **Flexibility**
- Easy to swap UI implementations
- Can run headless (set `ui_ = nullptr`)
- Can add multiple UIs (e.g., both ncurses and web UI)

### 3. **Maintainability**
- Clear separation of concerns
- Core logic independent of UI
- Easier to understand and modify

### 4. **Extensibility**
- Easy to add new event types
- Easy to add new UI implementations
- Can add event logging, metrics, etc.

---

## Migration Strategy

### Phase 1: Create Interface (Non-Breaking)
1. Create `lc_ui_interface.hpp`
2. Create `ncurses_ui` adapter that wraps `window_mgr`
3. Keep existing code working

### Phase 2: Refactor Core (Gradual)
1. Add event emission alongside direct calls
2. Make UI calls go through interface
3. Test thoroughly

### Phase 3: Remove Direct Dependencies
1. Remove `window_mgr&` parameter from `thread_run_core`
2. Remove global shared state
3. Use interface exclusively

### Phase 4: Cleanup
1. Remove old global variables
2. Update documentation
3. Add tests

---

## Alternative: Message Queue Approach

Instead of callbacks, use a message queue:

```cpp
class client_core {
private:
    std::queue<ui_event> event_queue_;
    std::mutex event_mutex_;
    
public:
    void emit_event(const ui_event& event) {
        std::lock_guard<std::mutex> lock(event_mutex_);
        event_queue_.push(event);
    }
    
    void process_ui_events(ui_interface* ui) {
        std::lock_guard<std::mutex> lock(event_mutex_);
        while (!event_queue_.empty()) {
            auto event = event_queue_.front();
            event_queue_.pop();
            
            switch (event.type) {
                case EVENT_MESSAGE:
                    ui->on_message_received(event.message);
                    break;
                // ... other events ...
            }
        }
    }
};
```

**Pros:**
- Decouples timing (events can be batched)
- Easier to add event logging
- Can prioritize events

**Cons:**
- More complex
- Potential memory growth if UI is slow

---

## Recommendation

**Use the Interface + Callback approach** (Step 1-4) because:
1. Simpler to implement
2. Lower latency (direct callbacks)
3. Easier to understand
4. Sufficient for current needs

Consider message queue if:
- UI becomes a bottleneck
- Need event replay/logging
- Multiple UI consumers

---

## Next Steps

1. **Review this design** - Does it meet your requirements?
2. **Create interface header** - Start with `lc_ui_interface.hpp`
3. **Implement ncurses adapter** - Wrap existing `window_mgr`
4. **Refactor core gradually** - One method at a time
5. **Add tests** - Verify decoupling works

Would you like me to start implementing this refactoring?


