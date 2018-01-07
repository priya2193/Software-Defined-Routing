#ifndef TOPOLOGY_H_
#define TOPOLOGY_H_
#include <vector>

uint16_t no_of_routers;
uint16_t periodic_interval;
char* ip_address[5];
uint16_t dist_vect[5][5];

struct router_topology{
	uint16_t router_id;
	uint16_t router_port;
	uint16_t data_port;
	uint16_t cost;
	uint32_t router_ip_address;
	int neighbour;
	char *ip_address;
};	

struct routing_table{
	uint16_t router_id;
	uint16_t padding;
	uint16_t next_hop_id;
	uint16_t cost;	
};
struct time_track{
	uint16_t router_id;
	clock_t init_time;
	clock_t start_time;
	clock_t after_sel_time;
};
struct update_routing_table{
	uint32_t router_ip_address;
	uint16_t router_port;
	uint16_t padding;
	uint16_t router_id;
	uint16_t cost;	
};
struct send_to_router{
	uint16_t no_of_update_fields;
	uint16_t source_router_port;
	uint32_t source_router_ip_address;
	update_routing_table table[5];
};
struct data_for_sendfile{
	uint32_t dest_ip_address;
	uint8_t init_ttl;
	uint8_t transfer_id;
	uint16_t init_seq_no;
	char filename[256];
};
struct data_packet_send_recv{
	uint32_t dest_ip_address;
	uint8_t transfer_id;
	uint8_t init_ttl;
	uint16_t seq_no;
	uint16_t padding1;
	uint16_t padding2;
	char data[1024];
};	
static int memory_flag,memory_flag1;
update_routing_table updated_routing_table[5];
send_to_router send_routing_table;	
send_to_router recv_routing_table;
data_for_sendfile file_from_controller;
data_packet_send_recv data_packet;
data_packet_send_recv recv_packet;
char *send_buffer = (char *)malloc(sizeof(char)*1036);
data_packet_send_recv *data_to_send = (struct data_packet_send_recv*)send_buffer;
char *forward_buffer = (char *)malloc(sizeof(char)*1036);
data_packet_send_recv *data_to_forward = (struct data_packet_send_recv*)forward_buffer;
char my_filename[256];
#endif