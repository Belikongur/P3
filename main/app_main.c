// CSTDLIB includes.
#include <esp_log.h>
#include <esp_random.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

// LowNet includes.
#include "chat.h"
#include "cli.h"
#include "command.c"
#include "crypt.h"
#include "lownet.h"
#include "ping.h"
#include "serial_io.h"
#include "testcases.h"
#include "utility.h"

void sign_triplets();
void cmd_protocol_test();
void store_frame(uint8_t sign, const lownet_frame_t* frame);
// Usage: help_command(NULL)
// Pre:   None, this command takes no arguments.
// Post:  A list of available commands has been written to the serial port.
void help_command(char*);

const command_t commands[] = {
    {"shout", "/shout MSG                  Broadcast a message.", shout_command},
    {"tell", "/tell ID MSG or @ID MSG      Send a message to a specific node", tell_command},
    {"ping", "/ping ID                     Check if a node is online", ping_command},
    {"date", "/date                        Print the current time", date_command},
    {"setkey", "/setkey [KEY|0|1]          Set the encryption key to use.  If no key is provided encryption is disabled", crypt_setkey_command},
    {"id", "/id                            Print your ID", id_command},
    {"testenc", "/testenc [STR]            Run STR through a encrypt/decrypt cycle to verify that encryption works", crypt_test_command},
    {"testsign", "/testsign                Verifies that signatures work SHA256 and RSA-decryption", sign_command},
    {"testbuffer", "/testbuffer            Sends 3 packets with different signatures to app dispatch", sign_triplets},
    {"testcmd", "/testcmd                  Sends a command protocol packet to app dispach", cmd_protocol_test},
    {"help", "/help                        Print this help", help_command}};

const size_t NUM_COMMANDS = sizeof commands / sizeof(command_t);
#define FIND_COMMAND(_command) (find_command(_command, commands, NUM_COMMANDS))

// Usage: help_command(NULL)
// Pre:   None, this command takes no arguments.
// Post:  A list of available commands has been written to the serial port.
void help_command(char*) {
    /*
            Loop Invariant:
            0 <= i < NUM_COMMANDS
            forall x | 0 <= x < i : commands[x] has been written to the serial port
     */
    for (size_t i = 0; i < NUM_COMMANDS; ++i)
        serial_write_line(commands[i].description);
    serial_write_line("Any input not preceded by a '/' or '@' will be treated as a broadcast message.");
}

void app_frame_dispatch(const lownet_frame_t* frame) {
    // Mask the signing bits.
    uint8_t sign_bits = ((frame->protocol & 0b11000000) >> 6);
    if (sign_bits != 0) {
        store_frame(sign_bits, frame);
        return;
    }
    switch (frame->protocol & 0b00111111) {
        case LOWNET_PROTOCOL_TIME:
            // Ignore TIME packets, deprecated.
            break;

        case LOWNET_PROTOCOL_CHAT:
            chat_receive(frame);
            break;

        case LOWNET_PROTOCOL_PING:
            ping_receive(frame);
            break;

        case LOWNET_PROTOCOL_COMMAND:
            command_receive(frame);
            break;
    }
}

void app_main(void) {
    char msg_in[MSG_BUFFER_LENGTH];
    char msg_out[MSG_BUFFER_LENGTH];

    // Initialize the serial services.
    init_serial_service();

    // Initialize the LowNet services.
    lownet_init(app_frame_dispatch, crypt_encrypt, crypt_decrypt);

    // Initialize the command module
    command_init();

    // Dummy implementation -- this isn't true network time!  Following 2
    //	lines are not needed when an actual source of network time is present.
    lownet_time_t init_time = {1, 0};
    lownet_set_time(&init_time);

    while (true) {
        memset(msg_in, 0, MSG_BUFFER_LENGTH);
        memset(msg_out, 0, MSG_BUFFER_LENGTH);

        if (!serial_read_line(msg_in)) {
            // Quick & dirty input parse.
            if (msg_in[0] == 0) continue;
            if (msg_in[0] == '/') {
                char* name = strtok(msg_in + 1, " ");
                command_fun_t command = FIND_COMMAND(name);
                if (!command) {
                    char buffer[17 + strlen(name) + 1];
                    sprintf(buffer, "Invalid command: %s", name);
                    serial_write_line(buffer);
                    continue;
                }
                char* args = strtok(NULL, "\n");
                serial_write_line(args);
                command(args);
            } else if (msg_in[0] == '@') {
                FIND_COMMAND("tell")
                (msg_in + 1);
            } else {
                // Default, chat broadcast message.
                FIND_COMMAND("shout")
                (msg_in);
            }
        }
    }
}

#define HASH_SIZE 32
#define SIGNATURE_SIZE 256
#define SIGN_FRAMES_NUM 3
static const lownet_frame_t* signed_frames[SIGN_FRAMES_NUM];
lownet_time_t signed_timestamp[SIGN_FRAMES_NUM];
uint8_t h_m[HASH_SIZE] = {0};
uint8_t h_k[HASH_SIZE] = {0};
uint8_t signature[SIGNATURE_SIZE] = {0};
uint8_t decrypted[SIGNATURE_SIZE] = {0};
size_t num_frames = SIGN_FRAMES_NUM;

void clear_frames() {
    memset(&signed_frames, 0, sizeof(signed_frames));
    memset(&signed_timestamp, 0, sizeof(signed_timestamp));
    memset(&h_m, 0, sizeof(h_m));
    memset(&h_k, 0, sizeof(h_k));
    num_frames = SIGN_FRAMES_NUM;
}

bool verify_timestamp() {
    lownet_time_t current_time = lownet_get_time();
    for (int i = 0; i < SIGN_FRAMES_NUM; i++) {
        if (compare_time(&signed_timestamp[i], &current_time) < 0 &&
            time_diff(&signed_timestamp[i], &current_time).seconds >= 10) {
            return false;
        }
    }
    return true;
}

bool verify_hash(const uint8_t* payload, const uint8_t* hash) {
    return memcmp(payload, hash, HASH_SIZE) == 0;
}

bool verify_rsa(uint8_t* rsa, uint8_t* h_m) {
    uint8_t zeros[220] = {0};
    uint8_t ones[4] = {1, 1, 1, 1};
    if (memcmp(decrypted, zeros, sizeof(zeros))) return false;
    if (memcmp(&decrypted[sizeof(zeros)], ones, sizeof(ones))) return false;
    if (memcmp(&decrypted[sizeof(zeros) + sizeof(ones)], h_m, HASH_SIZE)) return false;

    return true;
}

void store_frame(uint8_t sign, const lownet_frame_t* frame) {
    if (sign == 0 || sign > SIGN_FRAMES_NUM) return;
    signed_frames[sign - 1] = frame;
    signed_timestamp[sign - 1] = lownet_get_time();
    if (--num_frames > 0) return;

    if (!verify_timestamp()) {
        serial_write_line("Frame expired before verification. Triple not processed.");
        clear_frames();
        return;
    }

    const char* pem = lownet_get_signing_key();
    hash((const uint8_t*)pem, strlen(pem), h_k);
    if (!verify_hash(signed_frames[1]->payload, h_k) ||
        !verify_hash(signed_frames[2]->payload, h_k)) {
        serial_write_line("Hash of public key mismatch in signed frames. Triple not processed");
        clear_frames();
        return;
    }

    hash((const uint8_t*)signed_frames[0], LOWNET_FRAME_SIZE, h_m);
    if (!verify_hash(&signed_frames[1]->payload[HASH_SIZE], h_m) ||
        !verify_hash(&signed_frames[2]->payload[HASH_SIZE], h_m)) {
        serial_write_line("Hash of message mismatch in signed frames. Triple not processed");
        clear_frames();
        return;
    }

    memcpy(signature, &signed_frames[1]->payload[2 * HASH_SIZE], SIGNATURE_SIZE / 2);
    memcpy(&signature[SIGNATURE_SIZE / 2], &signed_frames[2]->payload[2 * HASH_SIZE], SIGNATURE_SIZE / 2);
    rsa(signature, decrypted);
    if (!verify_rsa(decrypted, h_m)) {
        serial_write_line("RSA signature mismatch in signed frames. Triple not processed");
        clear_frames();
        return;
    }

    ((lownet_frame_t*)signed_frames[0])->protocol &= 0b00111111;
    app_frame_dispatch(signed_frames[0]);
    clear_frames();
}

/*
 *  Test LowNet frame, with incorrect CRC, but we can sign it anyway!
 *
 *  Resulting SHA-256:
 *  4afdb5cf4fc366b493229e05182121342099d80b0651523537834ddba10c7871
 */
static const lownet_frame_t testframe_1 = {
    {0x10, 0x4e}, 1, 1,  // magic[2], source, destination
    1,
    7,
    {0, 0},     // proto, length, reserved[2]
    {1, 2, 3},  // payload (rest are zeroes)
    0           // CRC     (in correct)
};

/*
 *  RSA signature of the above testframe:
 *  - extracted from two signature frames
 */
static uint8_t test_signature[SIGNATURE_SIZE] = {
    /******************************** first half  ********************************/
    0x60, 0xd5, 0x4d, 0x4e, 0x48, 0xe9, 0xe3, 0xec, 0x46, 0x19, 0x31, 0x12, 0x74, 0x8b, 0x40, 0xeb,
    0xe0, 0xae, 0x97, 0x23, 0x84, 0x68, 0x6d, 0x8a, 0x92, 0x02, 0xc9, 0x58, 0x27, 0x7a, 0x24, 0x4b,
    0x4c, 0x9e, 0x68, 0xef, 0x81, 0xe5, 0x0b, 0x47, 0x7c, 0xa7, 0x63, 0x99, 0x95, 0x18, 0x78, 0xfe,
    0xa9, 0x07, 0x40, 0x1e, 0x0b, 0x22, 0x6a, 0x55, 0x02, 0xd4, 0xb1, 0x63, 0x9a, 0x1f, 0xfc, 0x9e,
    0xd0, 0x9b, 0xb6, 0x05, 0x82, 0x47, 0xf6, 0x49, 0xc4, 0xdf, 0x56, 0x95, 0x6c, 0xbf, 0x95, 0xb6,
    0x07, 0xea, 0x92, 0x0f, 0xe1, 0x9b, 0x72, 0x56, 0xd9, 0x3e, 0x4a, 0xdc, 0x7b, 0xb2, 0xea, 0xd9,
    0xe2, 0x25, 0x38, 0x85, 0x59, 0x3d, 0xf5, 0xef, 0x1a, 0x47, 0x0d, 0xb7, 0xed, 0xea, 0x89, 0xeb,
    0x52, 0x07, 0x17, 0xf0, 0x74, 0xeb, 0x19, 0x50, 0x70, 0x54, 0xfe, 0x39, 0x08, 0xec, 0xc3, 0x9f,
    /*******************************  second half  ********************************/
    0xec, 0x29, 0x93, 0xad, 0x4f, 0xff, 0xa5, 0xc2, 0x0a, 0x7f, 0x6b, 0x98, 0x85, 0xfc, 0xc8, 0x17,
    0xd4, 0x3c, 0xf6, 0x7c, 0x05, 0x9e, 0xc8, 0xa0, 0x18, 0x89, 0xf1, 0x10, 0x6e, 0xeb, 0x76, 0x62,
    0x96, 0x53, 0x70, 0xe4, 0xf8, 0x4b, 0x34, 0x23, 0xc1, 0xfb, 0x48, 0xb5, 0x69, 0xf4, 0x2b, 0x8a,
    0xa5, 0x1f, 0xd7, 0x06, 0xc0, 0x64, 0xcb, 0x82, 0x60, 0x86, 0x56, 0xd6, 0x45, 0x44, 0x0a, 0xa0,
    0x20, 0x65, 0x7a, 0x04, 0x38, 0xf6, 0x4d, 0x00, 0x9a, 0x1c, 0xb3, 0x14, 0x09, 0x17, 0xa9, 0xe4,
    0xf3, 0x65, 0x46, 0xf5, 0xf8, 0x22, 0xcb, 0x9d, 0x02, 0x66, 0x75, 0x7b, 0x5c, 0x90, 0x6b, 0xbb,
    0x23, 0xb5, 0xc9, 0x37, 0x0c, 0x64, 0xf9, 0xb3, 0x5b, 0x69, 0xd6, 0x81, 0xed, 0x7b, 0xdf, 0xfc,
    0xe2, 0x87, 0x7b, 0x42, 0x9f, 0x7c, 0x99, 0x61, 0xf4, 0x46, 0xb3, 0x69, 0xab, 0xb3, 0xe1, 0x64};

void sign_triplets() {
    lownet_frame_t first = {0};
    lownet_frame_t second = {0};

    memcpy(&first, &testframe_1, 8);
    memcpy(&second, &testframe_1, 8);

    uint8_t sign1 = (LOWNET_PROTOCOL_COMMAND | 0b10000000);
    uint8_t sign2 = (LOWNET_PROTOCOL_COMMAND | 0b11000000);

    // Message frame
    first.protocol = sign1;
    second.protocol = sign2;

    uint8_t hash_m[HASH_SIZE];
    hash((uint8_t*)&testframe_1, LOWNET_FRAME_SIZE, hash_m);

    const char* signing_key = lownet_get_signing_key();
    uint8_t pem[HASH_SIZE];
    hash((const uint8_t*)signing_key, strlen(signing_key), pem);

    memcpy(first.payload, pem, HASH_SIZE);
    memcpy(second.payload, pem, HASH_SIZE);
    memcpy(&first.payload[HASH_SIZE], hash_m, HASH_SIZE);
    memcpy(&second.payload[HASH_SIZE], hash_m, HASH_SIZE);

    memcpy(&first.payload[2 * HASH_SIZE], test_signature, SIGNATURE_SIZE / 2);
    memcpy(&second.payload[2 * HASH_SIZE], &test_signature[SIGNATURE_SIZE / 2], SIGNATURE_SIZE / 2);
    app_frame_dispatch(&testframe_1);
    app_frame_dispatch(&first);
    app_frame_dispatch(&second);
}

void cmd_protocol_test() {
    uint64_t sequence = 1;
    uint8_t command = 1;
    lownet_frame_t cmd = {0};
    cmd.magic[0] = 0x10;
    cmd.magic[1] = 0x4e;
    cmd.source = lownet_get_device_id();
    cmd.destination = lownet_get_device_id();
    cmd.protocol = LOWNET_PROTOCOL_COMMAND;
    cmd.length = 12;

    memcpy(cmd.payload, &sequence, sizeof(sequence));
    memcpy(&cmd.payload[sizeof(sequence)], &command, sizeof(command));

    lownet_time_t time = lownet_get_time();
    memcpy(&cmd.payload[sizeof(sequence) + sizeof(uint32_t)], &time, sizeof(lownet_time_t));
    app_frame_dispatch(&cmd);

    lownet_frame_t cmd2 = {0};
    char* message = "This is the message woop wooop";
    cmd2.magic[0] = 0x10;
    cmd2.magic[1] = 0x4e;
    cmd2.source = lownet_get_device_id();
    cmd2.destination = lownet_get_device_id();
    cmd2.protocol = LOWNET_PROTOCOL_COMMAND;
    cmd2.length = strlen(message);
    sequence = 3;
    command = 2;
    memcpy(cmd2.payload, &sequence, sizeof(sequence));
    memcpy(&cmd2.payload[sizeof(sequence)], &command, sizeof(command));
    memcpy(&cmd2.payload[sizeof(sequence) + sizeof(uint32_t)], message, strlen(message));
    app_frame_dispatch(&cmd2);

    lownet_frame_t cmd3 = {0};
    char* message2 = "This is NEW";
    cmd3.magic[0] = 0x10;
    cmd3.magic[1] = 0x4e;
    cmd3.source = lownet_get_device_id();
    cmd3.destination = lownet_get_device_id();
    cmd3.protocol = LOWNET_PROTOCOL_COMMAND;
    cmd3.length = strlen(message2);
    sequence = 2;
    memcpy(cmd3.payload, &sequence, sizeof(sequence));
    memcpy(&cmd3.payload[sizeof(sequence)], &command, sizeof(command));
    memcpy(&cmd3.payload[sizeof(sequence) + sizeof(uint32_t)], message2, strlen(message2));
    app_frame_dispatch(&cmd3);
}

void print_frame(const lownet_frame_t* frame) {
    printf("\n--------FRAME--------\n");
    for (int i = 0; i < sizeof(lownet_frame_t); i++) {
        uint8_t byte = ((uint8_t*)frame)[i];
        printf("%02x[%c]%c", byte, (byte > 31 && byte < 127) ? byte : ' ', ((i & 0xF) != 0xF) ? ' ' : '\n');
    }
    printf("\n");
    return;
}
