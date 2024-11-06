#ifndef COMMAND_H
#define COMMAND_H

#include <lownet.h>
#include <stdint.h>

#define CMD_HASH_SIZE 32
#define CMD_BLOCK_SIZE 256
#define MASTER_NODE_ID 0xF0

typedef struct __attribute__((__packed__)) {
    uint64_t sequence;
    uint8_t type;
    uint8_t reserved[3];
    uint8_t contents[180];
} cmd_packet_t;

typedef struct __attribute__((__packed__)) {
    uint8_t hash_key[CMD_HASH_SIZE];
    uint8_t hash_msg[CMD_HASH_SIZE];
    uint8_t sig_part[CMD_BLOCK_SIZE / 2];
} cmd_signature_t;

void command_init();

// Usage: time_command(cmd)
// Pre:
//   - cmd is a pointer to a cmd_packet_t structure that contains a new time value in its contents.
//   - cmd->contents must hold a valid lownet_time_t structure, containing time data in seconds and fractional parts.
// Post:
//   - Sets the system time using the time data from cmd->contents.
//   - Logs the new time if successful, or an error if the time could not be set.
void time_command(cmd_packet_t* cmd);

// Usage: test_command(cmd, frame)
// Pre:
//   - cmd is a pointer to a cmd_packet_t structure containing the command details and payload data in cmd->contents.
//   - frame is a pointer to a lownet_frame_t structure containing the frame metadata, including the length of the payload.
// Post:
//   - Sends a "ping" message to the master node with the payload from cmd->contents.
//   - Logs the node ID, payload, and payload length if successful, or an error if the ping fails.
void test_command(cmd_packet_t* cmd, const lownet_frame_t* frame);

// Usage: command_receive(frame)
// Pre:
//   - frame is a pointer to a lownet_frame_t structure containing the frame's payload and metadata.
//   - frame->payload must contain a cmd_packet_t structure with a valid command type and sequence number.
//   - cmd_packet_t::sequence must be greater than the previous sequence number seen for the command to be processed.
// Post:
//   - Processes the command based on its type: calls time_command for type 1 or test_command for type 2.
//   - Logs an error if the sequence number is not valid or if the command type is unknown.
void command_receive(const lownet_frame_t* frame);

#endif
