#include <linux/types.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define MIN_EXTERNAL_PORT 1024
#define MAX_EXTERNAL_PORT 65535
#define RECORD_TIMEOUT 60 /* in seconds */


/* Verbosity level */
//enum print_mode {PRINT_ALL, PRINT_BRIEF};

/* A node in our linked-list table 
struct table_record {
    uint8_t     internal_mac[ETH_ALEN];
    uint32_t    internal_ip;
    uint16_t    internal_port;
    uint32_t    external_ip;
    uint16_t    external_port;
    time_t      touch;
    struct table_record *next;
} *table;
*/

/* Our functions prototypes */
//void table_print(enum print_mode mode);
struct table_record *table_outbound(uint32_t internal_ip,
        uint8_t *internal_mac, uint16_t internal_port, uint32_t external_ip);
struct table_record *table_inbound(uint32_t external_ip,
        uint16_t external_port);
