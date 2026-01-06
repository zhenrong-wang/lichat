# Private Messaging Protocol Implementation

## Overview

Private messaging has been implemented at the protocol level, allowing the server to route messages to specific users or groups instead of broadcasting to all clients.

## Message Format

### Client-to-Server (Raw Message Body)

When sending a message, the client includes a recipient prefix in the message body:

- **Broadcast**: `BROADCAST|content` or just `content` (default)
- **Private (1-to-1)**: `TO:username|content`
- **Group**: `TO:user1,user2,user3|content`

The `|` character separates the recipient prefix from the message content.

### Server-to-Client (After Processing)

The server processes the message and sends it to recipients in the standard format:
```
from_user,timestamp,content
```

## Server Implementation

### Key Functions

1. **`parse_message_recipients()`** (static helper)
   - Parses recipient prefix from message body
   - Returns: `(is_broadcast, recipient_list, message_content)`
   - Handles `BROADCAST|`, `TO:user1,user2|`, or no prefix (default broadcast)

2. **`secure_targeted_send()`**
   - Routes messages to specific clients by username
   - Converts usernames to user emails (UIDs)
   - Looks up client connection info (CIF) for each recipient
   - Sends encrypted message (0x10) to each recipient
   - Returns number of successful sends

3. **`get_cinfo_by_username()`**
   - Helper to get client connection info (CIF) by username
   - Used by `secure_targeted_send()` to find recipient connections

### Message Routing Logic

When the server receives a message:
1. Parses recipient information using `parse_message_recipients()`
2. If broadcast → uses `secure_broadcasting()` (existing behavior)
3. If private/group → uses `secure_targeted_send()` to route to specific clients
4. Includes sender in recipient list so they see their own message

## Client Implementation

### Data Structures

The `chat_message` struct has been extended:
```cpp
struct chat_message {
    std::string from_user;
    std::string timestamp;
    std::string content;
    bool is_system;
    bool is_from_me;
    bool is_private;              // NEW: true for private/group messages
    std::vector<std::string> recipients;  // NEW: recipient usernames
};
```

### Current Status

- ✅ Protocol support: Client can receive and parse messages
- ✅ Data structures: Extended to support private message metadata
- ⏳ Message sending: Currently defaults to broadcast (no prefix)
- ⏳ UI integration: Pending recipient selection UI

## Usage Example

### Sending a Private Message

To send a private message to a user named "alice":
```
TO:alice|Hello, this is a private message!
```

### Sending a Group Message

To send a message to multiple users:
```
TO:alice,bob,charlie|Hello everyone in this group!
```

### Sending a Broadcast Message

To send a public message (default):
```
Hello, this is a public message!
```

Or explicitly:
```
BROADCAST|Hello, this is a public message!
```

## Next Steps (UI Layer)

1. **Recipient Selection UI**
   - Add UI controls to select recipient(s) when composing a message
   - Support single user selection for private messages
   - Support multiple user selection for group messages
   - Support "broadcast" option for public messages

2. **Message Formatting**
   - Update client to format messages with recipient prefix based on UI selection
   - Modify `get_input()` or add `get_input_with_recipients()` method

3. **Message Display**
   - Update UI to visually distinguish private/group messages from public messages
   - Show recipient list for group messages
   - Add indicators (e.g., "Private", "Group: alice, bob")

4. **Group Management**
   - Add UI for creating named groups
   - Store group memberships (could extend to database)
   - Allow quick selection of groups when sending messages

