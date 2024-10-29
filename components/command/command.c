#include "command.h"

#include <stdio.h>
#include <string.h>

#include "ping.h"

uint64_t sequence_num = 0;

void command_init() {
    // ...
}

void time_command(cmd_packet_t* cmd) {
    lownet_time_t time;
    memcpy(&time, &cmd->contents, sizeof(lownet_time_t));
    printf("New time set: %ld.%ds\n", time.seconds, time.parts);
    lownet_set_time(&time);
}

void test_command(cmd_packet_t* cmd, const lownet_frame_t* frame) {
    cmd->contents[frame->length] = '\0';
    printf("Pinged master node %02X with payload: %s of length: %d\n", MASTER_NODE_ID, cmd->contents, frame->length);
    ping(MASTER_NODE_ID, cmd->contents, frame->length);
}

void command_receive(const lownet_frame_t* frame) {
    cmd_packet_t* cmd = (cmd_packet_t*)frame->payload;

    if (cmd->sequence > sequence_num) {
        sequence_num = cmd->sequence;
    } else {
        printf("Sequence num: %lld is less than previously seen sequence num:%lld\n", cmd->sequence, sequence_num);
        return;
    }

    switch (cmd->type) {
        case 1:
            time_command(cmd);
            break;
        case 2:
            test_command(cmd, frame);
            break;
        default:
            printf("Unknown command type:%d\n", cmd->type);
            break;
    }
}

// For testing
// void print_cmd(cmd_packet_t* cmd) {
//     printf("\n--------COMMAND--------\n");
//     for (int i = 0; i < sizeof(cmd_packet_t); i++) {
//         uint8_t byte = ((uint8_t*)cmd)[i];
//         printf("%02x[%c]%c", byte, (byte > 31 && byte < 127) ? byte : ' ', ((i & 0xF) != 0xF) ? ' ' : '\n');
//     }
//     printf("\n");
//     return;
// }

// void print_frame(const lownet_frame_t* frame) {
//     printf("\n--------FRAME--------\n");
//     for (int i = 0; i < sizeof(lownet_frame_t); i++) {
//         uint8_t byte = ((uint8_t*)frame)[i];
//         printf("%02x[%c]%c", byte, (byte > 31 && byte < 127) ? byte : ' ', ((i & 0xF) != 0xF) ? ' ' : '\n');
//     }
//     printf("\n");
//     return;
// }