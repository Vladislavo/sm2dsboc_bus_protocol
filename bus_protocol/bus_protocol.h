#ifndef __BUS_PROTOCOL__H__
#define __BUS_PROTOCOL__H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BUS_PROTOCOL_BOARD_ID_WIS = 0,    // whisper node
    BUS_PROTOCOL_BOARD_ID_MKR,        // mkr1000
    BUS_PROTOCOL_BOARD_ID_ESP,        // esp32
    BUS_PROTOCOL_BOARD_ID_UNKNOWN = 0xFF
} board_id_t;

typedef enum {
    BUS_PROTOCOL_PACKET_TYPE_TRANSMIT_REQUEST = 0x11,
    BUS_PROTOCOL_PACKET_TYPE_TRANSMIT_GRANT = 0x12,
    BUS_PROTOCOL_PACKET_TYPE_DATA_SEND = 0x20,
    BUS_PROTOCOL_PACKET_TYPE_DATA_REQUEST = 0x23,
    BUS_PROTOCOL_PACKET_TYPE_REQUEST_TIME = 0x21,
    BUS_PROTOCOL_PACKET_TYPE_NETWORK_TIME = 0x22,
    BUS_PROTOCOL_PACKET_TYPE_ACK = 0x30,
    BUS_PROTOCOL_PACKET_TYPE_NACK = 0x31,
    BUS_PROTOCOL_PACKET_TYPE_UNKNOWN = 0xFF
} packet_type_t;

void bus_protocol_packet_encode(
    const packet_type_t packet_type,
    const uint8_t *data,
    const uint8_t data_length,
    uint8_t *packet,
    uint8_t *packet_length);

packet_type_t bus_protocol_packet_decode(
    const uint8_t *packet,
    const uint8_t packet_length, 
    uint8_t *data,
    uint8_t *data_length);

void bus_protocol_transmit_request_encode(
    const board_id_t board_id, 
    uint8_t *packet, 
    uint8_t *packet_length);

board_id_t bus_protocol_transmit_request_decode(
    const uint8_t *packet, 
    const uint8_t packet_length);

void bus_protocol_transmit_grant_encode(
    const board_id_t board_id, 
    uint8_t *packet, 
    uint8_t *packet_length);

board_id_t bus_protocol_transmit_grant_decode(
    const uint8_t *packet, 
    const uint8_t packet_length);

void bus_protocol_data_send_encode(
    const uint8_t *payload,
    const uint8_t payload_length,
    uint8_t *packet,
    uint8_t *packet_length);

void bus_protocol_data_request_encode(
    const board_id_t board_id,
    uint8_t *packet,
    uint8_t *packet_length);

void bus_protocol_request_time_encode(
    const board_id_t board_id,
    uint8_t *packet,
    uint8_t *packet_length);

board_id_t bus_protocol_request_time_decode(
    const uint8_t *packet,
    const uint8_t packet_length);

void bus_protocol_network_time_encode(
    const board_id_t board_id,
    const uint32_t utc,
    uint8_t *packet,
    uint8_t *packet_length);

uint8_t bus_protocol_network_time_decode(
    board_id_t *board_id,
    uint32_t *utc,
    const uint8_t *packet,
    const uint8_t *packet_length);

#ifdef __cplusplus
}
#endif

#endif // __BUS_PROTOCOL__H__