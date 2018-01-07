
/**
 * @priyamur_assignment3
 * @author  PRIYA MURTHY <priyamur@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * This contains the main function. Add further description here....
 */

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */
#include <string.h>
#include <stdio.h>
#include <iostream>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <find_ip.h>
#include <sys/queue.h>
#include <topology.h>
#include <netinet/in.h>
#include <sstream>
#include <sstream>
#include <fstream>
#include <sstream>
#include<cstring>
//#include <bits/stdc++>
using namespace std;


#define bytes_to_u16(MSB,LSB) (((unsigned int) ((unsigned char) MSB)) & 255)<<8 | (((unsigned char) LSB)&255)
typedef enum {FALSE, TRUE} bool_enum;
#define ERROR(err_msg) {perror(err_msg); exit(EXIT_FAILURE);}
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
uint16_t CONTROL_PORT;
fd_set master_list, watch_list;
int head_fd;
int var = 1;
static int my_router_id;
static int check_if_connection_exists = 0;

#define CNTRL_HEADER_SIZE 8
#define CNTRL_RESP_HEADER_SIZE 8
#define BLOCKSIZE 1024

#define PACKET_USING_STRUCT // Comment this out to use alternate packet crafting technique

#ifdef PACKET_USING_STRUCT
struct __attribute__((__packed__)) CONTROL_HEADER
{
    uint32_t dest_ip_addr;
    uint8_t control_code;
    uint8_t response_time;
    uint16_t payload_len;
};

struct __attribute__((__packed__)) CONTROL_RESPONSE_HEADER
{
    uint32_t controller_ip_addr;
    uint8_t control_code;
    uint8_t response_code;
    uint16_t payload_len;
};
#endif

#define AUTHOR_STATEMENT "I, priyamur, have read and understood the course academic integrity policy."

#ifndef PACKET_USING_STRUCT
#define CNTRL_RESP_CONTROL_CODE_OFFSET 0x04
#define CNTRL_RESP_RESPONSE_CODE_OFFSET 0x05
#define CNTRL_RESP_PAYLOAD_LEN_OFFSET 0x06
#endif

#ifndef PACKET_USING_STRUCT
#define CNTRL_CONTROL_CODE_OFFSET 0x04
#define CNTRL_PAYLOAD_LEN_OFFSET 0x06
#endif

int create_control_sock();
int new_control_conn(int sock_index);
bool isControl(int sock_index);
bool control_recv_hook(int sock_index);
void init_response(int sock_index, char *cntrl_payload);
void make_router_topology(char *cntrl_payload, int payload_len);
void init();
char* create_response_header(int sock_index, uint8_t control_code, uint8_t response_code, uint16_t payload_len);
ssize_t recvALL(int sock_index, char *buffer, ssize_t nbytes);
ssize_t sendALL(int sock_index, char *buffer, ssize_t nbytes);
void author_response(int sock_index);
void routing_table_response(int sock_index);
ssize_t recvALL(int sock_index, char *buffer, ssize_t nbytes);
ssize_t sendALL(int sock_index, char *buffer, ssize_t nbytes);
char* make_ip(uint32_t ip, int i);
void make_router_socket();
void create_routing_table(struct router_topology router[]);
void send_routing_update();
void bellman_ford();
void read_file(int sock,int sock1);
int receive_from_neighbours();
void connect_and_send_to_router_socket(int sockindex);
void extract_data_from_received_file(char *cntrl_payload1);
void print_update_routing_table_before_sending();
void find_my_router_id();
void find_my_neighbours();
void create_data_sock();
int new_data_plane_conn(int sock_index);
void update_init_routing_table();
void update_response(int sock_index);
void find_next_timeout_val(int router_id);
void init_update_routing_table();
void crash_response(int sock_index);
void update_cost(char *cntrl_payload);
int file_length();
int counter = 0;
void create_some_socket();
void send_after_receiving(char *recv_file);
void create_data_packet(char buffer[1024], int set);
void extract_sendfile_info(char *cntrl_payload,int payload_len);
struct router_topology router[5];
struct routing_table routing_table[5];
int control_socket, router_socket, data_socket;
const char *routing_table_result;
static int no_of_neighbours;
struct timeval timeout_val;
void sendfile_response(int sock_index);
int init_done = 0;
void write_to_file(char my_filename[256]);
int send_after_receiving_sock = -1;
int accepted_connection = 0;
static int crash_req_from_controller = 0;
char data_packet_to_send[1036];
void write_file();
char* find_filename();
uint32_t dest_ip_address;
int dest_flag = 0;
int fwd_flag = 0;
int file_open_flag = 0;
uint32_t fwd_dest_ip_address;
char*filename = (char*)malloc(sizeof(char)*1024);
static int recv_segments = 0;
int file_size;
std::stringstream file;
FILE* output_file;
uint32_t my_ip_address;
int main(int argc, char **argv)
{
    
    CONTROL_PORT = atoi(argv[1]);
    //create_some_socket();
    init();
    timeout_val.tv_sec = 1000;
    
    return 0;
}
void create_some_socket()
{
    ;
}
char* create_response_header(int sock_index, uint8_t control_code, uint8_t response_code, uint16_t payload_len)
{
    char *buffer;
#ifdef PACKET_USING_STRUCT
    /** ASSERT(sizeof(struct CONTROL_RESPONSE_HEADER) == 8)
     * This is not really necessary with the __packed__ directive supplied during declaration (see control_header_lib.h).
     * If this fails, comment #define PACKET_USING_STRUCT in control_header_lib.h
     */
    BUILD_BUG_ON(sizeof(struct CONTROL_RESPONSE_HEADER) != CNTRL_RESP_HEADER_SIZE); // This will FAIL during compilation itself; See comment above.
    
    struct CONTROL_RESPONSE_HEADER *cntrl_resp_header;
#endif
#ifndef PACKET_USING_STRUCT
    char *cntrl_resp_header;
#endif
    
    struct sockaddr_in addr;
    socklen_t addr_size;
    
    buffer = (char *) malloc(sizeof(char)*CNTRL_RESP_HEADER_SIZE);
#ifdef PACKET_USING_STRUCT
    cntrl_resp_header = (struct CONTROL_RESPONSE_HEADER *) buffer;
#endif
#ifndef PACKET_USING_STRUCT
    cntrl_resp_header = buffer;
#endif
    
    addr_size = sizeof(struct sockaddr_in);
    getpeername(sock_index, (struct sockaddr *)&addr, &addr_size);
    
#ifdef PACKET_USING_STRUCT
    /* Controller IP Address */
    memcpy(&(cntrl_resp_header->controller_ip_addr), &(addr.sin_addr), sizeof(struct in_addr));
    /* Control Code */
    cntrl_resp_header->control_code = control_code;
    /* Response Code */
    cntrl_resp_header->response_code = response_code;
    /* Payload Length */
    cntrl_resp_header->payload_len = htons(payload_len);
#endif
    
#ifndef PACKET_USING_STRUCT
    /* Controller IP Address */
    memcpy(cntrl_resp_header, &(addr.sin_addr), sizeof(struct in_addr));
    /* Control Code */
    memcpy(cntrl_resp_header+CNTRL_RESP_CONTROL_CODE_OFFSET, &control_code, sizeof(control_code));
    /* Response Code */
    memcpy(cntrl_resp_header+CNTRL_RESP_RESPONSE_CODE_OFFSET, &response_code, sizeof(response_code));
    /* Payload Length */
    payload_len = htons(payload_len);
    memcpy(cntrl_resp_header+CNTRL_RESP_PAYLOAD_LEN_OFFSET, &payload_len, sizeof(payload_len));
#endif
    
    return buffer;
}

ssize_t recvALL(int sock_index, char *buffer, ssize_t nbytes)
{
    ssize_t bytes = 0;
    bytes = recv(sock_index, buffer, nbytes, 0);
    //printf("recv Bytes %d, buffer %u \n",bytes, buffer);
    
    if(bytes == 0) return -1;
    while(bytes != nbytes)
        bytes += recv(sock_index, buffer+bytes, nbytes-bytes, 0);
    
    //printf("recv Bytes %d, buffer %u \n",bytes, buffer);
    // printf("RecvALL Buffer%s\n",buffer);
    return bytes;
}

ssize_t sendALL(int sock_index, char *buffer, ssize_t nbytes)
{
    ssize_t bytes = 0;
    bytes = send(sock_index, buffer, nbytes, 0);
    //printf("Bytes %d",bytes);
    if(bytes == 0) return -1;
    while(bytes != nbytes)
        bytes += send(sock_index, buffer+bytes, nbytes-bytes, 0);
    
    return bytes;
}

void author_response(int sock_index)
{
    uint16_t payload_len, response_len;
    char *cntrl_response_header, *cntrl_response_payload, *cntrl_response;
    
    payload_len = sizeof(AUTHOR_STATEMENT)-1; // Discount the NULL chararcter
    cntrl_response_payload = (char *) malloc(payload_len);
    memcpy(cntrl_response_payload, AUTHOR_STATEMENT, payload_len);
    
    cntrl_response_header = create_response_header(sock_index, 0, 0, payload_len);
    
    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    cntrl_response = (char *) malloc(response_len);
    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);
    /* Copy Payload */
    memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
    free(cntrl_response_payload);
    //printf("In author response: response %s\n",cntrl_response_payload);
    sendALL(sock_index, cntrl_response, response_len);
    
    free(cntrl_response);
}

/* Linked List for active control connections */
struct ControlConn
{
    int sockfd;
    LIST_ENTRY(ControlConn) next;
}*connection, *conn_temp;
LIST_HEAD(ControlConnsHead, ControlConn) control_conn_list;

int create_control_sock()
{
    int sock;
    struct sockaddr_in control_addr;
    socklen_t addrlen = sizeof(control_addr);
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
        ERROR("socket() failed");
    
    /* Make socket re-usable */
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int)) < 0)
        ERROR("setsockopt() failed");
    
    bzero(&control_addr, sizeof(control_addr));
    
    control_addr.sin_family = AF_INET;
    str = find_ip();
    //printf("%s\n",str);
    inet_pton(AF_INET, str, &control_addr.sin_addr);
    //printf("Router at %s:\n", inet_ntoa(control_addr.sin_addr));
    //control_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    //printf("Control port is %d\n",CONTROL_PORT);
    control_addr.sin_port = htons(CONTROL_PORT);
    
    if(bind(sock, (struct sockaddr *)&control_addr, sizeof(control_addr)) < 0)
        ERROR("bind() failed");
    
    if(listen(sock, 5) < 0)
        ERROR("listen() failed");
    
    LIST_INIT(&control_conn_list);
    
    return sock;
}

int new_control_conn(int sock_index)
{
    int fdaccept, caddr_len;
    struct sockaddr_in remote_controller_addr;
    
    caddr_len = sizeof(remote_controller_addr);
    fdaccept = accept(sock_index, (struct sockaddr *)&remote_controller_addr,(socklen_t*) &caddr_len);
    if(fdaccept < 0)
        ERROR("accept() failed");
    
    /* Insert into list of active control connections */
    connection = (struct ControlConn *)malloc(sizeof(struct ControlConn));
    connection->sockfd = fdaccept;
    LIST_INSERT_HEAD(&control_conn_list, connection, next);
    
    return fdaccept;
}

void remove_control_conn(int sock_index)
{
    LIST_FOREACH(connection, &control_conn_list, next) {
        if(connection->sockfd == sock_index) LIST_REMOVE(connection, next); // this may be unsafe?
        free(connection);
    }
    
    close(sock_index);
}

bool isControl(int sock_index)
{
    LIST_FOREACH(connection, &control_conn_list, next)
    if(connection->sockfd == sock_index) return TRUE;
    
    return FALSE;
}

bool control_recv_hook(int sock_index)
{
    char *cntrl_header, *cntrl_payload;
    uint8_t control_code;
    uint16_t payload_len;
    
    /* Get control header */
    cntrl_header = (char *) malloc(sizeof(char)*CNTRL_HEADER_SIZE);
    bzero(cntrl_header, CNTRL_HEADER_SIZE);
    
    if(recvALL(sock_index, cntrl_header, CNTRL_HEADER_SIZE) < 0){
        remove_control_conn(sock_index);
        free(cntrl_header);
        return FALSE;
    }
    
    /* Get control code and payload length from the header */
#ifdef PACKET_USING_STRUCT
    /** ASSERT(sizeof(struct CONTROL_HEADER) == 8)
     * This is not really necessary with the __packed__ directive supplied during declaration (see control_header_lib.h).
     * If this fails, comment #define PACKET_USING_STRUCT in control_header_lib.h
     */
    BUILD_BUG_ON(sizeof(struct CONTROL_HEADER) != CNTRL_HEADER_SIZE); // This will FAIL during compilation itself; See comment above.
    
    struct CONTROL_HEADER *header = (struct CONTROL_HEADER *) cntrl_header;
    control_code = header->control_code;
    payload_len = ntohs(header->payload_len);
#endif
#ifndef PACKET_USING_STRUCT
    memcpy(&control_code, cntrl_header+CNTRL_CONTROL_CODE_OFFSET, sizeof(control_code));
    memcpy(&payload_len, cntrl_header+CNTRL_PAYLOAD_LEN_OFFSET, sizeof(payload_len));
    payload_len = ntohs(payload_len);
#endif
    
    free(cntrl_header);
    
    /* Get control payload */
    if(payload_len != 0){
        cntrl_payload = (char *) malloc(sizeof(char)*payload_len);
        bzero(cntrl_payload, payload_len);
        
        if(recvALL(sock_index, cntrl_payload, payload_len) < 0){
            remove_control_conn(sock_index);
            
            free(cntrl_payload);
            return FALSE;
        }
    }
    
    /* Triage on control_code */
    switch(control_code){
        case 0:
            author_response(sock_index);
            break;
            
        case 1: init_response(sock_index, cntrl_payload);
            make_router_topology(cntrl_payload,payload_len);
            create_routing_table(router);
            //timeout_val.tv_sec = periodic_interval;
            init_update_routing_table();
            init_done = 1;
            timeout_val.tv_sec = periodic_interval;
            make_router_socket();
            create_data_sock();
            
            break;
            
        case 2: //create_routing_table(router);
            print_update_routing_table_before_sending();
            routing_table_response(sock_index);
            break;
            
        case 3: update_cost(cntrl_payload);
            update_response(sock_index);
            break;
        case 4: crash_response(sock_index);
            crash_req_from_controller = 1;
            exit(0);
            break;
        case 5: extract_sendfile_info(cntrl_payload,payload_len);
            connect_and_send_to_router_socket(sock_index);
            //printf("Here in case 5\n");
            break;
    }
    
    if(payload_len != 0) free(cntrl_payload);
    return TRUE;
}

void main_loop()
{
    int selret, sock_index, fdaccept;
    
    
    while(var){
        watch_list = master_list;
        selret = select(head_fd+1, &watch_list, NULL, NULL, &timeout_val);
        
        if(selret < 0)
            perror("select failed.");
        else if(selret == 0 && init_done == 1)
        {
            //printf("Sending routing update\n");
            send_routing_update();
            timeout_val.tv_sec = periodic_interval;
            
        }
        
        /* Loop through file descriptors to check which ones are ready */
        for(sock_index=0; sock_index<=head_fd; sock_index+=1){
            //cout<<"Sock idex"<<sock_index<<" "<<"Data socket"<<data_socket<<endl;
            if(FD_ISSET(sock_index, &watch_list)){
                
                /* control_socket */
                if(sock_index == control_socket){
                    fdaccept = new_control_conn(sock_index);
                    
                    /* Add to watched socket list */
                    FD_SET(fdaccept, &master_list);
                    if(fdaccept > head_fd) head_fd = fdaccept;
                }
                
                /* router_socket */
                else if(sock_index == router_socket){
                    //call handler that will call recvfrom() .....
                    int from_router_id = receive_from_neighbours();
                    bellman_ford();
                    //printf("Received from router id %d\n",from_router_id);
                    //bellman_ford();
                }
                
                /* data_socket */
                else if(sock_index == data_socket){
                    //cout<<"I'm here in sock_index == data_socket"<<endl;
                    char buffer[1036] = {0};
                    
                    int accept = new_data_plane_conn(sock_index);
                    //read(accept, buffer, 1036);
                    // if(recvALL(accept, buffer, 1036) < 0)
                    //cout<<"wrong receive!!";
                    //send_after_receiving(buffer);
                    accepted_connection = accept;
                    
                    FD_SET(accept, &master_list);
                    if(accept > head_fd) head_fd = accept;
                    
                }
                
                else{
                    
                    if((isControl(sock_index))){
                        if(!control_recv_hook(sock_index)) FD_CLR(sock_index, &master_list);
                    }
                    
                    else
                    {
                        
                        //cout<<"I'm in mah new place!"<<endl;
                        char *buffer = (char*)malloc(1036);
                        //cout<<"Vlue of count: "    << counter<<endl;
                        counter++;
                        recvALL(sock_index, buffer, 1036);
                        send_after_receiving(buffer);
                        free(buffer);
                        
                    }
                    
                }
                
                
                //else if isData(sock_index);
                // else perror("Unknown socket index");
                
            }
        }
    }
}

void init()
{
    
    control_socket = create_control_sock();
    
    //router_socket and data_socket will be initialized after INIT from controller
    
    FD_ZERO(&master_list);
    FD_ZERO(&watch_list);
    
    /* Register the control socket */
    FD_SET(control_socket, &master_list);
    head_fd = control_socket;
    
    main_loop();
}

void init_response(int sock_index, char* cntrl_payload)
{
    uint16_t payload_len, response_len;
    char *cntrl_response_header, *cntrl_response_payload, *cntrl_response;
    
    
    //payload_len = sizeof(AUTHOR_STATEMENT)-1; // Discount the NULL chararcter
    cntrl_response_payload = (char *) malloc(payload_len);
    //memcpy(cntrl_response_payload, AUTHOR_STATEMENT, payload_len);
    
    payload_len = 0;
    cntrl_response_header = create_response_header(sock_index, 1, 0, 0);
    
    
    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    cntrl_response = (char *) malloc(response_len);
    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);
    /* Copy Payload */
    memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
    free(cntrl_response_payload);
    //printf("In author response: response %s\n",cntrl_response_payload);
    sendALL(sock_index, cntrl_response, response_len);
    
    free(cntrl_response);
}

void make_router_topology(char *cntrl_payload, int payload_len)
{
    char *str = (char*)malloc(sizeof(char)*2);
    char *ip_addr = (char*)malloc(sizeof(char)*4);
    no_of_routers = (uint16_t)cntrl_payload[1] | cntrl_payload[0]<<8  ;
    periodic_interval = (uint16_t)cntrl_payload[3] | cntrl_payload[2]<<8;
    int k = 4;
    
    for(int i =0; i < no_of_routers; i++)
    {
        
        router[i].router_id = (uint8_t)cntrl_payload[k+1] | (uint8_t)cntrl_payload[k]<<8;
        router[i].router_port = (uint8_t)cntrl_payload[k+3] | (uint8_t)cntrl_payload[k+2]<<8;
        router[i].data_port = (uint8_t)cntrl_payload[k+5] | (uint8_t)cntrl_payload[k+4]<<8;
        router[i].cost = (uint8_t)cntrl_payload[k+7] | (uint8_t)cntrl_payload[k+6]<<8;
        router[i].router_ip_address = (uint32_t)((uint8_t)cntrl_payload[k+11] | (uint8_t)cntrl_payload[k+10]<<8 | (uint8_t)cntrl_payload[k+9]<<16 | (uint8_t)cntrl_payload[k+8]<<24);
        
        k += 12;
        //std::cout<<"k"<<k<<"\n";
    }
    //print
    //cout <<no_of_routers <<endl;
    //printf("No of routers %u, periodic interval %u\n",no_of_routers,periodic_interval);
    
    //print routing table
    /*for(int i = 0; i< no_of_routers; i++)
     {
     printf("Router id %u, Router port %u, Data Port %u,Cost %u, IP address %u\n",router[i].router_id,router[i].router_port,router[i].data_port,router[i].cost,router[i].router_ip_address);
     }*/
    
    for(int i =0; i<no_of_routers; i++)
    {
        ip_address[i] = (char*)malloc(sizeof(char)*1024);
        router[i].ip_address  = (char*)malloc(sizeof(char)*1024);
        ip_address[i] = make_ip(router[i].router_ip_address,i);
        router[i].ip_address = make_ip(router[i].router_ip_address,i);
        //printf("ip %d, %s \n",i,ip_address[i]);
    }
    //create_routing_table(router);
    //make_router_socket();
    find_my_router_id();
    find_my_neighbours();
    
}

namespace patch
{
    //https://stackoverflow.com/questions/12975341/to-string-is-not-a-member-of-std-says-g-mingw
    template < typename T > std::string to_string( const T& n )
    {
        std::ostringstream stm ;
        stm << n ;
        return stm.str() ;
    }
}

char* make_ip(uint32_t ip,int i)
{
    //Reference https://stackoverflow.com/questions/1680365/integer-to-ip-address-c
    unsigned int bytes[4];
    std::string ip_str;
    //const char *result = (char*)malloc(sizeof(char)*20);
    const char *dot = ".";
    //int dot = atoi(dot1);
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    //printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
    std::string temp = patch::to_string(bytes[3]);
    std::string temp1 = patch::to_string(bytes[2]);
    std::string temp2 = patch::to_string(bytes[1]);
    std::string temp3 = patch::to_string(bytes[0]);
    string ips= "";
    ips = temp + "."+ temp1 + "."+temp2+ "." +temp3;
    //cout<<"ips"<<ips<<"\n";
    char *result = (char *)ips.c_str();
    //cout<<result<<"\n";
    //strcpy(ip_address[i],result);
    ip_address[i] = result;
    //cout<<ip_address[i]<<"\n";
    //printf("%s\n",ip_address[i]);
    //delete result;
    //if(i==1)
    //ip_addr1 = result;
    return result;
}


void make_router_socket()
{
    struct sockaddr_in router_addr; int id, router_port;
    router_socket = socket(AF_INET, SOCK_DGRAM, 0);
    router_addr.sin_family = AF_INET;
    //cout<<"Here\n";
    //cout<<str<<"\n";
    str = find_ip();
    /* Make socket re-usable */
    if(setsockopt(router_socket, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int)) < 0)
        ERROR("setsockopt() failed");
    for(int i =0; i<no_of_routers; i++)
    {
        if(router[i].cost == 0)
            router_port = router[i].router_port;
        
    }
    //printf("Router port is: %d\n",router_port);
    router_addr.sin_port = htons(router_port);
    inet_pton(AF_INET, str, &router_addr.sin_addr);
    //serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(router_addr.sin_zero, '\0', sizeof router_addr.sin_zero);
    
    
    if(bind(router_socket, (struct sockaddr *) &router_addr, sizeof(router_addr)) < 0)
        ERROR("bind() failed");
    
    FD_SET(router_socket, &master_list);
    if(router_socket > head_fd) head_fd = router_socket;
    time_t timer;
    time(&timer);
    clock_t startTime = clock();
    //start_time = 0;
    
    
}
void find_my_router_id()
{
    for(int i =0; i< no_of_routers; i++)
    {
        if(router[i].cost == 0)
        {
            my_router_id = router[i].router_id;
            my_ip_address = router[i].router_ip_address;
            break;
        }
    }
    //printf("My router id is:%d\n",my_router_id);
    
    
}

void create_routing_table(struct router_topology router[])
{
    //printf("In create routing table\n");
    find_my_router_id();
    for(int i =0; i<no_of_routers; i++)
    {
        routing_table[i].router_id = htons(router[i].router_id);
        routing_table[i].padding = htons(0);
        if(routing_table[i].router_id == my_router_id)
        {
            routing_table[i].cost =htons(0);
            routing_table[i].next_hop_id = htons(my_router_id);
        }
        else
        {
            routing_table[i].cost = htons(router[i].cost);
            if(router[i].cost == 65535)
            {
                routing_table[i].next_hop_id = htons(65535);
            }
            else
                routing_table[i].next_hop_id = htons(router[i].router_id);
        }
        //printf("Cost %u of i %d\n",routing_table[i].cost,i);
    }
    /*for(int i = 0; i< no_of_routers; i++)
     {
     printf("Router id %u, Padding %u, Next hop id %u,Cost %u\n",routing_table[i].router_id,routing_table[i].padding,routing_table[i].next_hop_id,routing_table[i].cost);
     }*/
    //for(int i=0; i<5; i++)
    //cout<<"Id:"<<routing_table[i].router_id<<" "<<"Padding:"<<routing_table[i].padding<<" "<<"Next_hop_id:"<<routing_table[i].next_hop_id<<" "<<"Cost"<<routing_table[i].cost<<"\n";
    
    
}

void routing_table_response(int sock_index)
{
    uint16_t payload_len, response_len;
    static int first_time = 1;
    char *cntrl_response_header, *cntrl_response_payload, *cntrl_response;
    payload_len = 8*no_of_routers;
    //payload_len = sizeof(routing_table);
    //payload_len = sizeof(routing_table_result); // Discount the NULL chararcter
    //printf("Payload len %d\n",payload_len);
    if(first_time)
    {
        cntrl_response_payload = (char *) malloc(payload_len);
        //memcpy(cntrl_response_payload, routing_table_result, payload_len);
        memcpy(cntrl_response_payload, routing_table, payload_len);
        //printf("Control response payload %s\n",cntrl_response_payload);
        cntrl_response_header = create_response_header(sock_index,2, 0, payload_len);
        first_time = 0;
    }
    else
    {
        update_init_routing_table();
        cntrl_response_payload = (char *) malloc(payload_len);
        //memcpy(cntrl_response_payload, routing_table_result, payload_len);
        memcpy(cntrl_response_payload, routing_table, payload_len);
        //printf("Control response payload %s\n",cntrl_response_payload);
        cntrl_response_header = create_response_header(sock_index,2, 0, payload_len);
    }
    
    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    cntrl_response = (char *) malloc(response_len);
    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);
    /* Copy Payload */
    memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
    free(cntrl_response_payload);
    //printf("In author response: response %s\n",cntrl_response_payload);
    sendALL(sock_index, cntrl_response, response_len);
    
    free(cntrl_response);
}

void init_update_routing_table()
{
    for(int i=0; i<no_of_routers; i++)
    {
        updated_routing_table[i].router_id = router[i].router_id;
        updated_routing_table[i].padding = 0;
        updated_routing_table[i].cost = router[i].cost;
        updated_routing_table[i].router_port = router[i].router_port;
        updated_routing_table[i].router_ip_address = router[i].router_ip_address;
        //cout<<"Router id "<<updated_routing_table[i].router_id<<"Padding "<<updated_routing_table[i].padding<<"Cost "<<updated_routing_table[i].cost<<"Router port "<<updated_routing_table[i].router_port<<"Router ip address "<<updated_routing_table[i].router_ip_address<<"\n";
    }
    
}
void find_my_neighbours()
{
    for(int i =0; i<no_of_routers;i++)
    {
        if(router[i].cost != 65535 && router[i].cost != 0)
        {
            //printf("Router id %u\n",router[i].router_id);
            //my_neighbours[no_of_neighbours] = router[i].router_port;
            router[i].neighbour = 1;
            no_of_neighbours++;
        }
    }
    //printf("No of neighbours = %d\n",no_of_neighbours);
    //for(int i=0; i<no_of_neighbours;i++)
    //{
    //printf("Neighbour id: %u \n",my_neighbours[i]);
    //}
}
void bellman_ford()
{
    //printf("In bellman ford\n");
    uint16_t q;
    uint16_t from_router_id = 0,from_router_port = 0;
    uint16_t cost=0,temp=0;
    
    for(int i =0 ; i<no_of_routers; i++)
    {
        if(recv_routing_table.source_router_port == router[i].router_port)
        {
            from_router_id = router[i].router_id;
            from_router_port = recv_routing_table.source_router_port;
            cost = router[i].cost;
            break;
        }
    }
    //cout<<"From router id"<<from_router_id;
    if(from_router_port != 0)
    {
        
        for(int i =0; i<no_of_routers; i++)
        {
            if(router[i].router_id!= from_router_id && router[i].router_id !=my_router_id)
            {
                temp = updated_routing_table[i].cost;
                if(temp > cost + recv_routing_table.table[i].cost)
                {
                    updated_routing_table[i].cost = cost + recv_routing_table.table[i].cost;
                    routing_table[i].cost = htons(updated_routing_table[i].cost);
                    routing_table[i].next_hop_id = htons(from_router_id);
                    
                }
            }
        }
    }
}
void send_routing_update()
{
    //sendto(dgram_socket, secret_message, strlen(secret_message)+1, 0, (struct sockaddr*)&dest, sizeof dest);
    //const char secret_message[1024]="Hi from router\n";
    char *table_to_neighbours;
    uint16_t len = 12*no_of_routers +8;
    //secret_message = "Hi from router\n";
    struct sockaddr_in dest_addr; int id, router_port;
    dest_addr.sin_family = AF_INET;
    
    str = find_ip();
    
    
    for(int i =0 ; i<no_of_routers; i++)
    {
        send_routing_table.table[i].router_ip_address = updated_routing_table[i].router_ip_address;
        send_routing_table.table[i].router_port = updated_routing_table[i].router_port;
        send_routing_table.table[i].padding = updated_routing_table[i].padding;
        send_routing_table.table[i].router_id = updated_routing_table[i].router_id;
        send_routing_table.table[i].cost = updated_routing_table[i].cost;
        //cout<<send_routing_table.table[i].router_ip_address<< "|";
        //cout<<send_routing_table.table[i].router_port<< "|";
        //cout<<send_routing_table.table[i].padding<< "|";
        //cout<<send_routing_table.table[i].router_id<< "| ";
        //cout<<send_routing_table.table[i].cost<<"\n";
    }
    for(int i = 0; i<no_of_routers; i++)
    {
        if(router[i].cost == 0)
        {
            
            send_routing_table.source_router_ip_address = router[i].router_ip_address;
            send_routing_table.source_router_port = router[i].router_port;
        }
    }
    send_routing_table.no_of_update_fields = no_of_routers;
    //send_routing_table.table = updated_routing_table;
    for(int i=0; i<no_of_routers; i++)
    {
        if(router[i].neighbour == 1)
        {
            int send_to_sock = socket(AF_INET,SOCK_DGRAM,0);
            size_t bytes = 12*no_of_routers + 8;
            dest_addr.sin_port = htons(router[i].router_port);
            dest_addr.sin_addr.s_addr = inet_addr(router[i].ip_address);
            //cout<<"Sending to Router_port: "<<router[i].router_port<<"Address"<<router[i].ip_address<<"\n";
            //table_to_neighbours = (char *) malloc(len);
            //memcpy(table_to_neighbours,send_routing_table, len);
            sendto(send_to_sock,&send_routing_table, sizeof(send_routing_table), 0, (struct sockaddr*)&dest_addr, sizeof (dest_addr));
        }
    }
}
void print()
{
    //printf("Here in update routing table!!\n");
    for(int i=0; i<no_of_routers; i++)
    {
        updated_routing_table[i].cost = dist_vect[my_router_id -1][i];
        //cout<<"Router id "<<updated_routing_table[i].router_id<<"Padding "<<updated_routing_table[i].padding<<"Cost "<<updated_routing_table[i].cost<<"Router port "<<updated_routing_table[i].router_port<<"Router ip address "<<updated_routing_table[i].router_ip_address<<"Next hop "<<routing_table[i].next_hop_id<<"Next hop ntohs"<<ntohs(routing_table[i].next_hop_id)<<"\n";
    }
}
int receive_from_neighbours()
{
    struct sockaddr_in router_addr;
    socklen_t l = sizeof(router_addr);
    recvfrom(router_socket,&recv_routing_table,sizeof(recv_routing_table),0,(struct sockaddr *)&router_addr,&l);
    //printf("Received\n");
    //cout<<"Source ip address "<<recv_routing_table.source_router_ip_address<<" "<<"Source port "<<recv_routing_table.source_router_port<<"\n";
    for(int i =0 ; i<no_of_routers;i++)
    {
        /*cout<<recv_routing_table.table[i].router_ip_address<<" ";
         cout<<recv_routing_table.table[i].router_port<<" ";
         cout<<recv_routing_table.table[i].padding<<" ";
         cout<<recv_routing_table.table[i].router_id<<" ";
         cout<<recv_routing_table.table[i].cost<<"\n";
         cout<<"Next hop "<<ntohs(routing_table[i].next_hop_id)<<"\n";*/
    }
    
    int from_router_id;
    for(int i =0; i<no_of_routers; i++)
    {
        //printf("Router address sin.port %u\n",ntohs(router_addr.sin_port));
        if(router[i].router_port == ntohs(router_addr.sin_port))
        {
            from_router_id = router[i].router_id;
        }
    }
    //cout << "Seconds passes now"<<1 + ltm->tm_sec << endl;
    //printf("After timer initializaton\n");
    //printf("Buffer %s for router_id %u start_time %d seconds %f\n", buffer,router_timer[from_router_id -1].router_id,router_timer[from_router_id -1].start_time,((float)router_timer[from_router_id -1].start_time)/CLOCKS_PER_SEC);
    //bellman_ford();
    bellman_ford();
    
    //print();
    return from_router_id;
}

void update_init_routing_table()
{
    for(int i =0; i<no_of_routers; i++)
    {
        routing_table[i].cost = htons(updated_routing_table[i].cost);
    }
}
void print_update_routing_table_before_sending()
{
    //for(int i =0 ; i<no_of_routers;i++)
    //{
    /*cout<<ntohs(routing_table[i].router_id)<<" ";
     cout<<ntohs(routing_table[i].padding)<<" ";
     cout<<ntohs(routing_table[i].next_hop_id)<<" ";
     cout<<ntohs(routing_table[i].cost)<<"\n";*/
    /*cout<<routing_table[i].router_id<<" ";
     cout<<routing_table[i].padding<<" ";
     cout<<routing_table[i].next_hop_id<<" ";
     cout<<routing_table[i].cost<<"\n";*/
    
    //}
}

void crash_response(int sock_index)
{
    uint16_t payload_len, response_len;
    char *cntrl_response_header, *cntrl_response_payload, *cntrl_response;
    
    
    //payload_len = sizeof(AUTHOR_STATEMENT)-1; // Discount the NULL chararcter
    cntrl_response_payload = (char *) malloc(payload_len);
    //memcpy(cntrl_response_payload, AUTHOR_STATEMENT, payload_len);
    
    payload_len = 0;
    cntrl_response_header = create_response_header(sock_index, 4, 0, 0);
    
    
    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    cntrl_response = (char *) malloc(response_len);
    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);
    /* Copy Payload */
    memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
    free(cntrl_response_payload);
    //printf("In author response: response %s\n",cntrl_response_payload);
    sendALL(sock_index, cntrl_response, response_len);
    
    free(cntrl_response);
}
void update_cost(char *cntrl_payload)
{
    uint16_t router_id, router_cost;
    router_id = (uint8_t)cntrl_payload[1] | (uint8_t)cntrl_payload[0]<<8;
    router_cost = (uint8_t)cntrl_payload[3] | (uint8_t)cntrl_payload[2]<<8;
    
    //cout<<router_id<<" "<<router_cost<<"\n";
    
    for(int i=0;i<no_of_routers;i++)
    {
        if(router[i].router_id == router_id)
        {
            routing_table[i].cost = htons(router_cost);
            updated_routing_table[i].cost = router_cost;
            routing_table[i].next_hop_id = htons(router_id);
        }
    }
    bellman_ford();
}
void update_response(int sock_index)
{
    uint16_t payload_len, response_len;
    char *cntrl_response_header, *cntrl_response_payload, *cntrl_response;
    
    
    //payload_len = sizeof(AUTHOR_STATEMENT)-1; // Discount the NULL chararcter
    cntrl_response_payload = (char *) malloc(payload_len);
    //memcpy(cntrl_response_payload, AUTHOR_STATEMENT, payload_len);
    
    payload_len = 0;
    cntrl_response_header = create_response_header(sock_index, 3, 0, 0);
    
    
    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    cntrl_response = (char *) malloc(response_len);
    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);
    /* Copy Payload */
    memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
    free(cntrl_response_payload);
    //printf("In author response: response %s\n",cntrl_response_payload);
    sendALL(sock_index, cntrl_response, response_len);
    
    free(cntrl_response);
}
void extract_sendfile_info(char *cntrl_payload,int payload_len)
{
    file_from_controller.dest_ip_address = (uint32_t)((uint8_t)cntrl_payload[3] | (uint8_t)cntrl_payload[2]<<8 | (uint8_t)cntrl_payload[1]<<16 | (uint8_t)cntrl_payload[0]<<24);
    file_from_controller.init_ttl = (uint8_t)cntrl_payload[4];
    file_from_controller.transfer_id = (uint8_t)cntrl_payload[5];
    file_from_controller.init_seq_no = (uint8_t)cntrl_payload[7] | (uint8_t)cntrl_payload[6]<<8;
    
    int filename_len = payload_len - 8;
    //file_from_controller.filename = (char*)malloc(sizeof(char)*filename_len);
    //memset(&file_from_controller.filename,0,sizeof(char)*filename_len);
    memcpy(file_from_controller.filename,(cntrl_payload+8),filename_len);
    //cout<<filename_len<<file_from_controller.filename<<endl;
    //<<file_from_controller.dest_ip_address<<" "<<(int)file_from_controller.init_ttl<<" "<<(int)file_from_controller.transfer_id<<" "<<(int)file_from_controller.init_seq_no<<" "<<file_from_controller.filename<<"\n";
    int len = file_length();
    //cout<<"File length"<<file_length();
}
void create_data_sock()
{
    
    struct sockaddr_in control_addr;
    socklen_t addrlen = sizeof(control_addr);
    uint16_t my_data_port;
    data_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(data_socket < 0)
        ERROR("socket() failed");
    
    /* Make socket re-usable */
    if(setsockopt(data_socket, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int)) < 0)
        ERROR("setsockopt() failed");
    
    bzero(&control_addr, sizeof(control_addr));
    
    control_addr.sin_family = AF_INET;
    str = find_ip();
    //printf("%s\n",str);
    inet_pton(AF_INET, str, &control_addr.sin_addr);
    //printf("Router at %s:\n", inet_ntoa(control_addr.sin_addr));
    //control_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    //printf("Control port is %d\n",CONTROL_PORT);
    for(int i =0; i<no_of_routers; i++)
    {
        if(router[i].router_id == my_router_id)
        {
            my_data_port = router[i].data_port;
        }
    }
    //cout<<"My data port "<<my_data_port<<"\n";
    control_addr.sin_port = htons(my_data_port);
    
    if(bind(data_socket, (struct sockaddr *)&control_addr, sizeof(control_addr)) < 0)
        ERROR("bind() failed");
    
    if(listen(data_socket, 5) < 0)
        ERROR("listen() failed");
    
    FD_SET(data_socket, &master_list);
    if(data_socket > head_fd) head_fd = data_socket;
    
}

int new_data_plane_conn(int sock_index)
{
    int fdaccept, caddr_len;
    struct sockaddr_in remote_controller_addr;
    
    caddr_len = sizeof(remote_controller_addr);
    fdaccept = accept(sock_index, (struct sockaddr *)&remote_controller_addr,(socklen_t*) &caddr_len);
    if(fdaccept < 0)
        ERROR("accept() failed");
    
    
    return fdaccept;
}

void connect_and_send_to_router_socket(int sockindex)
{
    struct sockaddr_in address;
    int sock = -1, valread;
    struct sockaddr_in serv_addr;
    char *send_to_ip = (char*)malloc(sizeof(char)*256);
    memset(send_to_ip, '0', sizeof(send_to_ip));
    uint16_t send_to_port;
    uint16_t temp;
    char hello[] = "Hello from client";
    char buffer[1024] = {0};
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        //printf("\n Socket creation error \n");
        return;
    }
    
    memset(&serv_addr, '0', sizeof(serv_addr));
    for(int i =0; i<no_of_routers; i++)
    {
        if(router[i].router_id == my_router_id)
        {
            if(router[i].router_ip_address == file_from_controller.dest_ip_address)
            {
                //cout<<"Yayyyyy!reached destination";
                //write_file();
                /*std::stringstream file;
                 ofstream output_file;
                 if(file_open_flag == 0)
                 {
                 string temp;
                 file <<"file-";
                 file<<int(data_to_forward->transfer_id);
                 temp = file.str();
                 filename = (char*)temp.c_str();
                 //cout<<filename<<"Filename";
                 output_file.open(filename,std::ios_base::app);
                 file_open_flag = 1;
                 }
                 //output_file<<data_to_forward->data;
                 //output_file.close();
                 if(recv_segments == 10240)
                 {
                 output_file.write(recv_packet.data,1024);
                 memset(recv_packet.data,0,1024);
                 recv_segments = 1;
                 output_file.close();
                 }
                 recv_segments++;
                 output_file.write(recv_packet.data,1024);
                 /*if(recv_segments == file_size)
                 write_to_file(my_filename);
                 else
                 recv_segments++;*/
                return;
            }
            
        }
        else if(router[i].router_ip_address == file_from_controller.dest_ip_address)
        {
            temp = ntohs(routing_table[i].next_hop_id);
            //cout<<"Next router id"<<(int)temp<<"\n";
        }
    }
    for(int i=0;i<no_of_routers;i++)
    {
        if(router[i].router_id == temp)
        {
            strcpy(send_to_ip,router[i].ip_address);
            send_to_port = router[i].data_port;
        }
    }
    //cout<<"IP"<<send_to_ip<<"Port"<<(int)send_to_port<<"\n";
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(send_to_port);
    
    if(inet_pton(AF_INET, send_to_ip, &serv_addr.sin_addr)<=0)
    {
        //printf("\nInvalid address/ Address not supported \n");
        return;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        //printf("\nConnection Failed \n");
        return;
    }
    //cout<<"File sock index"<<sock<<endl;
    read_file(sock,sockindex);
}

int file_length()
{
    //https://stackoverflow.com/questions/2409504/using-c-filestreams-fstream-how-can-you-determine-the-size-of-a-file
    
    std::streampos fsize = 0;
    std::ifstream file1(file_from_controller.filename, std::ios::binary );
    
    fsize = file1.tellg();
    file1.seekg( 0, std::ios::end );
    fsize = file1.tellg() - fsize;
    file1.close();
    //cout<<"In file length\n";
    
    return (int)fsize;
}
char data_from_file[1024];
void read_file(int sock,int sock1)
{
    //https://ubuntuforums.org/showthread.php?t=2165380
    
    FILE *file_handle;
    //file_from_controller.filename
    file_handle = fopen(file_from_controller.filename,"r");
    int segments = file_length()/1024;
    //cout<<"File length"<<file_length()<<"Segments"<<segments<<endl;
    if(file_handle == NULL)
    {
        //printf("Unable to open file\n");
    }
    /*while(segments!=0)
     {
     int val = fread(data_from_file,sizeof(data_from_file[0]),1024,file_handle);
     //cout<<"Read"<<val;
     if(val > 0)
     {
     //data_from_file[1024]='\0';
     //cout<<"I'm here" <<data_from_file<<endl;
     //printf("I'm here%s\n",data_from_file);
     if(segments == 1)
     {
     create_data_packet(data_from_file,1);
     }
     else
     {
     create_data_packet(data_from_file,0);
     }
     //cout<<"Sock Index"<<sock<<endl;
     sendALL(sock , send_buffer , sizeof(char)*1036);
     memset(&data_from_file,0,1024);
     }
     
     segments--;
     }*/
    int i;
    for(i =1; i<=10240;i++)
    {
        int val = fread(data_from_file,sizeof(data_from_file[0]),1024,file_handle);
        
        if(i == 10240)
            create_data_packet(data_from_file,1);
        else
            create_data_packet(data_from_file,0);
        sendALL(sock , send_buffer , sizeof(char)*1036);
        memset(&data_from_file,0,1024);
    }
    
    cout<<"Value of i: "<<i<<endl;
    
    //if(segments == 0)
    sendfile_response(sock1);
    fclose(file_handle);
    
}
void create_data_packet(char buffer[1024], int set)
{
    int flag = 0;
    
    create_some_socket();
    static int fin = set;
    data_to_send->dest_ip_address = htonl(file_from_controller.dest_ip_address);
    //cout<<"Data with ip"<<" "<<ntohl(data_to_send->dest_ip_address)<<endl;
    data_to_send->transfer_id = file_from_controller.transfer_id;
    //cout<<"Data with ip and transfer id"<<" "<<data_to_send<<endl;
    data_to_send->init_ttl = file_from_controller.init_ttl;
    if(flag == 0)
    {
        flag = 1;
        data_to_send->seq_no = htons(file_from_controller.init_seq_no);
    }
    else
    {
        data_to_send->seq_no = htons(file_from_controller.init_seq_no + 1);
    }
    
    if(fin == 0)
    {
        data_to_send->padding1 = htons(0);
        data_to_send->padding2 = htons(0);
    }
    else
    {
        data_to_send->padding1 = htons(0x8000);
        data_to_send->padding2 = htons(0);
    }
    /*if(memory_flag == 0)
     {
     strcpy(data_to_send->data,file_from_controller.filename);
     memory_flag =1;
     }
     else*/
    strcpy(data_to_send->data,buffer);
    
    
    
}
void send_after_receiving(char *recv_file)
{
    extract_data_from_received_file(recv_file);
    struct sockaddr_in address;
    int valread;
    struct sockaddr_in serv_addr;
    char *send_to_ip = (char*)malloc(sizeof(char)*256);
    memset(send_to_ip, '0', sizeof(send_to_ip));
    uint16_t send_to_port;
    uint16_t temp;
    char hello[] = "Hello from client";
    char buffer[1024] = {0};
    
    
    //cout<<"I'm here";
    //cout<<"Router ip address"<<router[i].router_ip_address;
    //cout<<"Recv packet"<<recv_packet.dest_ip_address;
    //if(my_ip_address == dest_ip_address)
    //{
    
    if(file_open_flag == 0)
    {
        string temp;
        file <<"file-";
        file<<int(data_to_forward->transfer_id);
        temp = file.str();
        filename = (char*)temp.c_str();
        cout<<filename<<"Filename";
        output_file = fopen(filename,"a");
        file_open_flag = 1;
        dest_flag = 0;
    }
    
    
    //cout<<"Value of recvd segments: "<<recv_segments;
    fwrite(forward_buffer+12,sizeof(char), 1024, output_file);
    memset(forward_buffer,0,1036);
    recv_segments++;
    if(recv_packet.padding1 == 0x8000)
    {
        file_open_flag = 0;
        dest_flag = 0;
        //cout<<"I'm here";
        fclose(output_file);
    }
    
    //}
    
    //cout<<"Wrote 1024"<<endl;
    //memset(recv_packet.data,0,1024);
    //output_file.close();
    /*if(recv_segments < 10240)
     {
     recv_segments++;
     }
     else if(recv_segments == 10240)
     {
     file_open_flag = 0;
     dest_flag = 0;
     cout<<"Reached here\n";
     }*/
    
    //cout<<"Yayyyyy!reached destination"<<endl;
    return;
    //}
    for(int i = 0; i<no_of_routers; i++)
    {
        if(router[i].router_ip_address == dest_ip_address)
        {
            temp = ntohs(routing_table[i].next_hop_id);
            //cout<<"Next router id"<<(int)temp<<"\n";
        }
    }
    
    if(send_after_receiving_sock == -1)
    {
        //cout<<"File sock index"<<send_after_receiving_sock<<endl;
        
        if((send_after_receiving_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            //printf("\n Socket creation error \n");
            return;
        }
        
        memset(&serv_addr, '0', sizeof(serv_addr));
        
        for(int i=0;i<no_of_routers;i++)
        {
            if(router[i].router_id == temp)
            {
                strcpy(send_to_ip,router[i].ip_address);
                send_to_port = router[i].data_port;
            }
        }
        //cout<<"IP"<<send_to_ip<<"Port"<<(int)send_to_port<<"\n";
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(send_to_port);
        
        if(inet_pton(AF_INET, send_to_ip, &serv_addr.sin_addr)<=0)
        {
            //printf("\nInvalid address/ Address not supported \n");
            return;
        }
        
        if (connect(send_after_receiving_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            //printf("\nConnection Failed \n");
            return;
        }
        
        if(data_to_forward->init_ttl != 0)
        {
            data_to_forward->init_ttl = data_to_forward->init_ttl -1;
            //cout<<"TTL"<<int(data_to_forward->init_ttl)<<"recv packet TTL"<<int(recv_packet.init_ttl);
            //cout<<"sending from middle!"<<endl;
            send(send_after_receiving_sock,forward_buffer,sizeof(char)*1036,0);
        }
        else
            return;
    }
    else
    {
        //cout<<"File sock index"<<send_after_receiving_sock<<"TTL "<<int(data_to_forward->init_ttl)<<endl;
        
        //if(data_to_forward->init_ttl != 0)
        //{
        //data_to_forward->init_ttl = data_to_forward->init_ttl -1;
        sendALL(send_after_receiving_sock,forward_buffer,sizeof(char)*1036);
        
        //}
        //else
        //return;
    }
    
}


void extract_data_from_received_file(char *cntrl_payload1)
{
    
    recv_packet.dest_ip_address = (uint32_t)((uint8_t)cntrl_payload1[3] | (uint8_t)cntrl_payload1[2]<<8 | (uint8_t)cntrl_payload1[1]<<16 | (uint8_t)cntrl_payload1[0]<<24);
    if(dest_flag == 0)
    {
        dest_ip_address = recv_packet.dest_ip_address;
        dest_flag = 1;
    }
    recv_packet.transfer_id = (uint8_t)cntrl_payload1[4];
    recv_packet.init_ttl = (uint8_t)cntrl_payload1[5];
    recv_packet.seq_no = (uint16_t)(uint8_t)cntrl_payload1[7] | (uint8_t)cntrl_payload1[6]<<8;
    recv_packet.padding1 = (uint8_t)cntrl_payload1[9] | (uint8_t)cntrl_payload1[8]<<8;
    recv_packet.padding2 = (uint8_t)cntrl_payload1[11] | (uint8_t)cntrl_payload1[10]<<8;
    memcpy(recv_packet.data,cntrl_payload1+12,sizeof(char)*1024);
    
    uint32_t dest_ip = htonl(recv_packet.dest_ip_address);
    uint32_t transfer_id = recv_packet.transfer_id;
    uint32_t ttl = recv_packet.init_ttl;
    uint32_t seq_no = htons(recv_packet.seq_no);
    uint32_t padding1= htons(recv_packet.padding1);
    uint32_t padding2 = htons(recv_packet.padding2);
    //memcpy(dat
    //memcpy(data_to_forward->data,cntrl_payload1+12,sizeof(char)*1024);
    
    memcpy(forward_buffer, &dest_ip, 4);
    memcpy(forward_buffer + 4, &transfer_id, 1);
    memcpy(forward_buffer+ 5, &ttl, 1);
    memcpy(forward_buffer+ 6, &seq_no, 2);
    memcpy(forward_buffer+ 8, &padding1, 2);
    memcpy(forward_buffer + 10,&padding2, 2);
    memcpy(forward_buffer + 12,cntrl_payload1+12,1024);
    
    
    //cout<<"Extracting data from received file\n";
    //cout<<data_to_forward->dest_ip_address<<" "<<(int)data_to_forward->transfer_id<<" "<<(int)data_to_forward->init_ttl<<" "<<" "<<int(data_to_forward->seq_no)<<" "<<(int)data_to_forward->padding1<<" "<<(int)data_to_forward->padding2<<" "<<"\n";
    /*if(memory_flag1 == 0)
     {
     strcpy(my_filename,cntrl_payload1+12);
     //cout<<my_filename<<endl;
     memory_flag1 = 1;
     }*/
}


void sendfile_response(int sock_index)
{
    uint16_t payload_len, response_len;
    char *cntrl_response_header, *cntrl_response_payload, *cntrl_response;
    
    
    //payload_len = sizeof(AUTHOR_STATEMENT)-1; // Discount the NULL chararcter
    cntrl_response_payload = (char *) malloc(payload_len);
    //memcpy(cntrl_response_payload, AUTHOR_STATEMENT, payload_len);
    
    payload_len = 0;
    cntrl_response_header = create_response_header(sock_index, 5, 0, 0);
    
    
    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    cntrl_response = (char *) malloc(response_len);
    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);
    /* Copy Payload */
    memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
    free(cntrl_response_payload);
    //printf("In author response: response %s\n",cntrl_response_payload);
    sendALL(sock_index, cntrl_response, response_len);
    
    free(cntrl_response);
}






//./controller -t example.topology -i 1 -f 1 2 8 3 1 lets_test.txt
