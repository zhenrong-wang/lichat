# How to send and receive long messages reliably using UDP?

- [How to send and receive long messages reliably using UDP?](#how-to-send-and-receive-long-messages-reliably-using-udp)
  - [0. Abstract](#0-abstract)
  - [1. Prerequisites](#1-prerequisites)
  - [2. Methodology](#2-methodology)
  - [3. Send/Recv](#3-sendrecv)
  - [4. Limitations](#4-limitations)

## 0. Abstract

This is a design to send/recv long messages reliably on the current secure UDP communication protocol, to be discussed.

## 1. Prerequisites

With the secure UDP communication protocol of LightChat, we can try to send and receive long messages reliably. 

## 2. Methodology

Long messages are different from short messages because UDP is unreliable by its design, so we need to handle both packet order and packet loss. 

Therefore, we need to follow a mechanism:

- Each long message has a random unique message_id, aka `msg_uid`
- Each long message is divided into chunks/blocks, and each chunk/block has a fixed length, e.g. 4096 bytes. For UDP communication, each chunk should be restricted to 65536 bytes.
- Therefore, a long message could be expressed by: (`number_of_chunks` `chunk_size` `last_chunk_bytes`).
- A long message could be either **encrypted** or **signed**. Please refer to the secure UDP communication protocol.
- Above the secure layer (**encrypted** or **signed**), a chunk packet starts with a variable-length header:
  - `chunk_sn_width` : 4-bits.
    -  `0000` - 1-byte serial number (0~255)
    -  `0001` - 2-byte serial number (0~65535)
    -  *Other values are invalid in the current design.
  - `chunk_size`: 4-bits. 
    - `0000` - 32     bytes (MINIMUM)
    - `0001` - 64     bytes 
    - `0010` - 128    bytes
    - `0011` - 256    bytes
    - `0100` - 512    bytes
    - `0101` - 1024   bytes (MEDIUM)
    - `0110` - 2048   bytes
    - `0111` - 4096   bytes 
    - `1000` - 8192   bytes (not recommended)
    - `1001` - 16384  bytes (not recommended)
    - `1010` - 32768  bytes (not recommended)
    - `1011` - 64512  bytes (MAXIMUM, not recommended)
    - *Other values are invalid in the current design.
  - `chunk_sn_bytes` : it is related to the `chunk_sn_width`. That is:
    - if the `chunk_sn_width` corresponds to 1 byte, the `chunk_sn_bytes` would be 1 byte.
    - else, the `chunk_sn_bytes` would be 2 bytes.
  - So the chunke packet header might be 2 bytes or 3 bytes, that is:
    - 2 bytes: 0000 XXXX    XXXX XXXX
    - 3 bytes: 1111 XXXX    XXXX XXXX    XXXX XXXX
- Following the header is the `chunk_msg_body` with a size either equals to or smaller than the `chunk_size`. 
  - If the `chunk_msg_body` equals to the `chunk_size`, it is not the last chunk.
  - Otherwise, it is the last chunk of this packet. 
  - To avoid problems for those messages with (SIZE % `chunk_size` == 0), we require these messages must send an extra blank `chunk_msg_body` with only a header as their ends.

## 3. Send/Recv

To make the whole process reliable, we need to follow a mechanism:

- The receiver needs to maintain a `bitmap` to record the arrival of `chunk_packets`. If the `chunk_sn_width` is `0x00`, the receiver `bitmap` would be `64 bytes` (aka, 256 / 8); if the `chunk_sn_width` is other value, the receiver `bitmap` would be `8192 bytes` (aka, 65536 / 8).
- For each chunk packet, the receiver would record and cache it at its arrival.
- There could be a `time_window` (e.g. 3 secs) and a `maximum retry` (e.g. 3) to make the send/recv reliable. Which means, the receiver would check the `bitmap` to figure out which chunks are not received in the time window, and send retry requests to the sender. 
- If all chunk packets received, the receiver would assemble all the `chunk_msg_body`s with their serial numbers, and then provide to the upper level application.

## 4. Limitations

The design above can handle UDP messages with a theoretical maximum size of (65536 chunks * 64512 bytes / chunk) = 4,186,368 bytes ~ 4 GigaBytes.

In practical, we would recommend using 1024 byte as the `chunk_size`, so 64 MB long message could be handled properly.