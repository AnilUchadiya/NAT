#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <time.h>
#include <linux/types.h>
#include "table.h"


#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define MIN_EXTERNAL_PORT 1024
#define MAX_EXTERNAL_PORT 65535
#define RECORD_TIMEOUT 60 /* in seconds */
#include "table.h"
/* A node in our linked-list table */
struct table_record {
    uint8_t     internal_mac[ETH_ALEN];
    uint32_t    internal_ip;
    uint16_t    internal_port;
    uint32_t    external_ip;
    uint16_t    external_port;
    time_t      touch;
    struct table_record *next;
} table;

/**
 * Get the mapped external port for a record
 ********************************************************************************change this mapping according to NAT type******************************************************************************
 * @param internal_ip   The internal IP address
 * @param internal_port The internal port
 * @param external_ip   The external IP address
 * @return The mapped port (or 0 if not found)
 */

uint16_t table_get_external_port(uint32_t internal_ip, uint16_t internal_port,
        uint16_t external_ip)
{
    uint16_t external_port = 0;
    struct table_record *record;

    srand(time(NULL));
/*----------------------------------------------------------------------dynamic ip allocation------------------------------------------------------------------------------*/
    do 
    {
        external_port = rand() % (MAX_EXTERNAL_PORT - MIN_EXTERNAL_PORT) + MIN_EXTERNAL_PORT;
        for (record = table; record && record->external_port != external_port;record = record->next);
    } while (record);

    return external_port;
}


/**
 ********************************************************************************Adds a record in the table************************************************************************
 ****
 * @param internal_ip   The internal IP address
 * @param internal_mac  The internal MAC address
 * @param internal_port The internal port
 * @param external_ip   The external IP address
 * @return The new added record (beginning of the table)
 */

struct table_record *table_add(uint32_t internal_ip, uint8_t *internal_mac,
        uint16_t internal_port, uint32_t external_ip)
{
    struct table_record *record;

    if ((record = (struct table_record *)malloc(sizeof(struct table_record)))
            == NULL) {
        perror("Unable to allocate a new record");
        return NULL;
    }

    memcpy(record->internal_mac, internal_mac, ETH_ALEN); /* broadcast */
    record->internal_ip = internal_ip;
    record->internal_port = internal_port;
    record->external_ip = external_ip;
    record->external_port = table_get_external_port(internal_ip, internal_port,
external_ip);
    record->touch = time(NULL); /* current timestamp */

    if (table) {
        record->next = table;
        table = record;
    } else {
        table = record;
    }

    return table;
}




/**
 ************************************************************ Proccess an outcomming packet and delete old records********************************************************************
 * @param internal_ip   The internal IP address
 * @param internal_mac  The internal MAC address
 * @param internal_port The internal port#include "table.h"
 * @param external_ip   The external IP address
 * @return The corresponding record
 */
struct table_record *table_outbound(uint32_t internal_ip,
        uint8_t *internal_mac,
        uint16_t internal_port,
        uint32_t external_ip)
{
    struct table_record *record = table;
    struct table_record *before = NULL;

    while (record) {
        if (record->internal_ip == internal_ip &&
                record->internal_port == internal_port &&
                record->external_ip == external_ip) {
            record->touch = time(NULL); /* touch! */
            return record;
        }

        /* obsolete record */
        if (before && record->touch < time(NULL) + RECORD_TIMEOUT) { 
            before->next = record->next;
            free(record);
        }

        before = record;
        record = record->next;
    }

    return table_add(internal_ip, internal_mac, internal_port, external_ip);
}

/**
 ****************************************************************************** Proccess an incomming packet *******************************************************************************
 *
 * @param external_ip   The external IP address
 * @param external_port The external port
 * @return The corresponding record
 */
struct table_record *table_inbound(uint32_t external_ip,
        uint16_t external_port)
{
    struct table_record *record = table;

    while (record) {
        if (record->external_ip == external_ip &&
                record->external_port == external_port &&
                record->touch < time(NULL) + RECORD_TIMEOUT) {
            record->touch = time(NULL); /* touch! */
            return record;
        }

        record = record->next;
    }

#ifdef DEBUG
    fprintf(stderr, 
            "Warning: incomming packet from unknown tuple (IP, port)\n");
#endif

   // return NULL; /* packet should be ignored or returned to sender */
}

