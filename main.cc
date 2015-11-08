/*

Copyright (C) 2015 Robert Thoelen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/


#include "boost/property_tree/ptree.hpp"
#include "boost/property_tree/ini_parser.hpp"
#include "boost/algorithm/string.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>

char version[] = "NXCORE Manager, Kenwood, version 1.0";
char copyright[] = "Copyright (C) Robert Thoelen, 2015";

struct rpt {
	struct sockaddr_in rpt_addr_00; // socket address for 64000
	struct sockaddr_in rpt_addr_01; //socket address for 64001
	char *hostname;
	int time_since_rx;  // in seconds
	int time_since_tx;  // in seconds
	int hold_time;  // how long to hold talkgroup
	int tx_hold_time;  // how long to hold talkgroup after tx
	int rx_activity;     // flag to show receive activity
	int tx_busy;     // flag to show transmit activity
	unsigned int busy_tg;     // talkgroup being transmitted
	int stealth; // send heartbeat or not
	int vp_count; // count voice packets for 64001 packets
	unsigned char local_ran; // RAN for local operations
	unsigned char ran;	
	unsigned int active_tg; // talkgroup currently active
	unsigned int last_tg;  // used for talk group hold time
	unsigned int *tg_list;   // if a talkgroup isn't in this list, it isn't repeated
	unsigned int *tac_list;   // Tactical talkgroups (only comes through if received) 
	int uid; // need this for Kenwood udp 64001 data

} *repeater;


// RAN is at up_packet[24]

char up_packet[28] = { 0x8a, 0xcc, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, \
			0x4b, 0x57, 0x4e, 0x45, 0x00, 0x00, 0x00, 0x00, \
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, \
			0x01, 0x01, 0x00, 0x00 };

char down_packet[20] = { 0x8b, 0xcc, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, \
			0x4b, 0x57, 0x4e, 0x45, 0x00, 0x00, 0x00, 0x00, \
			0x01, 0x00, 0x00, 0x00 };


void rpton_64001(int);
void shutdown_64001(int);
void snd_packet(unsigned char [], int, int,int, int);
int tg_lookup(int, int);

int repeater_count;

unsigned int tempaddr;

time_t tm;

int socket_00, socket_01;   // Sockets we use

// See if incoming packet address matches a repeater.  If it does,
// return the index to it.  Otherwise return -1 for no match

int get_repeater_id(struct sockaddr_in *addr)
{
	int i;

	for(i = 0; i < repeater_count; i++)
	{	
		if((in_addr_t)addr->sin_addr.s_addr == (in_addr_t)repeater[i].rpt_addr_00.sin_addr.s_addr)
		{
			return i;
		}
	}

	return(-1);
}

struct sockaddr_in myaddr_00;
struct sockaddr_in myaddr_01;

void *listen_thread(void *thread_id)
{
        struct sockaddr_in remaddr;     /* remote address */
        socklen_t addrlen = sizeof(remaddr);            /* length of addresses */
        int recvlen;                    /* # bytes received */
        unsigned char buf[80];     /* receive buffer */
	struct hostent *he;
	int rpt_id;
	int strt_packet;

	struct sockaddr_in tport; // This is a test port to reflect what is received
	int GID, UID;

        /* create UDP socket for repeaters */

        if ((socket_00 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                perror("cannot create socket\n");
                return 0;
        }

        if ((socket_01 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                perror("cannot create socket\n");
                return 0;
        }

        /* bind the socket to any valid IP address and a specific port */


        memset((char *)&myaddr_00, 0, sizeof(myaddr_00));
        myaddr_00.sin_family = AF_INET;
//	myaddr_00.sin_addr.s_addr = inet_addr("10.44.0.1");
        myaddr_00.sin_addr.s_addr = htonl(INADDR_ANY);
        myaddr_00.sin_port = htons(64000);

        if (bind(socket_00, (struct sockaddr *)&myaddr_00, sizeof(myaddr_00)) < 0) {
                perror("bind failed");
                return 0;
        }

        memset((char *)&myaddr_01, 0, sizeof(myaddr_01));
        myaddr_01.sin_family = AF_INET;
        myaddr_01.sin_addr.s_addr = htonl(INADDR_ANY);
//	myaddr_01.sin_addr.s_addr = inet_addr("10.44.0.1");
        myaddr_01.sin_port = htons(64001);

        if (bind(socket_01, (struct sockaddr *)&myaddr_01, sizeof(myaddr_01)) < 0) {
                perror("bind failed");
                return 0;
        }


	// Set up the test port
	memset((char *)&tport, 0, sizeof(tport));
	tport.sin_family = AF_INET;
	tport.sin_addr.s_addr = inet_addr("127.0.0.1");
	tport.sin_port = htons(50000);

        /* now loop, receiving data and printing what we received */
        for (;;) {
                recvlen = recvfrom(socket_00, buf, 80, 0, (struct sockaddr *)&remaddr, &addrlen);
		time(&tm);
                if (recvlen == 47) {
                        buf[recvlen] = 0;
			GID = (buf[31] << 8) + buf[34];
			UID = (buf[29] << 8) + buf[32];

			rpt_id = get_repeater_id(&remaddr);
			if (rpt_id == -1)
			{
				std::cout << ctime(&tm) << " Unauthorized repeater, " << inet_ntoa(remaddr.sin_addr) << ", dropping packet" << std::endl;
				continue;  // Throw out packet, not in our list
			}
			repeater[rpt_id].uid = UID;

			if(buf[28] == 1) // Beginning of packets
			{
				repeater[rpt_id].rx_activity = 1;
				repeater[rpt_id].active_tg = GID;
				repeater[rpt_id].busy_tg = GID;
				strt_packet = 1;
				std::cout << ctime(&tm) << "Repeater " << rpt_id << " receiving start from UID: " << UID << " from TG: " << GID << std::endl;

			}
		
			if(buf[28] == 8) // End, sent shutdown on 64001	
			{
				repeater[rpt_id].rx_activity = 0;    // Activity on channel is over
				repeater[rpt_id].last_tg = repeater[rpt_id].active_tg;
				repeater[rpt_id].active_tg = 0;   
				strt_packet = 0;
				std::cout << ctime(&tm) << "Repeater " << rpt_id << " receiving stop from UID: " << UID << " from TG: " << GID << std::endl;
			}	
				
			repeater[rpt_id].time_since_rx = 0;
			// send packet to repeaters
			snd_packet(buf, recvlen, GID, rpt_id, strt_packet);

			sendto(socket_00, buf, recvlen, 0, (struct sockaddr *)&tport,
		 		sizeof(tport));
				
		}
                
		if (recvlen == 59) {

			rpt_id = get_repeater_id(&remaddr);
			if (rpt_id == -1)
			{
				std::cout << ctime(&tm) << "Unauthorized repeater, " << inet_ntoa(remaddr.sin_addr) << ", dropping packet" << std::endl;
				continue;  // Throw out packet, not in our list
			}	

			// Heartbeat packet from another repeater, bounce back
			// but then continue 
			if (buf[0] == 0x00)
			{
				
				sendto(socket_00, buf, recvlen, 0, (struct sockaddr *)&repeater[rpt_id].rpt_addr_00,
		 			sizeof(repeater[rpt_id].rpt_addr_00));
				continue; 
			}

			repeater[rpt_id].time_since_rx = 0;	
			GID = repeater[rpt_id].active_tg;

			// send packet to repeaters that can receive it
			snd_packet(buf, recvlen, GID, rpt_id, 0);
			sendto(socket_00, buf, recvlen, 0, (struct sockaddr *)&tport,
		 		sizeof(tport));
		}
		
        }	
}

void snd_packet(unsigned char buf[], int recvlen, int GID, int rpt_id, int strt_packet)
{
	int i, j;
	int tg;
	in_addr_t tmp_addr;

	// This blocks talkgroups received on a repeater that don't match
	// the talkgroup list

	if (tg_lookup(GID, rpt_id) == -1)
	{
		std::cout << ctime(&tm) << "Repeater " << rpt_id << " blocked, unauthorized talkgroup" << GID << std::endl;
		return;
	}


	// Sending selection logic

	for(i = 0; i < repeater_count; i++)
	{
	
		// Don't reflect our own packets back

		if (rpt_id == i)
			continue;

		// Is the talkgroup being sent in this repeater's list? If not, stop here

		tg = tg_lookup(GID, i);
		if (tg != -1)

		{		
		
			// First, if this particular repeater just had RX activity, if the packet 
			// doesn't match the last talkgroup, drop it.  This should solve most contention
			// issues

			if(repeater[i].last_tg != GID)
			{
				if(repeater[i].time_since_rx < repeater[i].hold_time)
				{
					std::cout << ctime(&tm) << "Blocking TG: " << GID << " sent on Repeater " << i << " due to recent RX on TG: " << repeater[i].last_tg << std::endl;
					continue;
				}
			}

			// Next, we need to determine if we need to preempt a talkgroup
			// Talkgroups that are on the left in the NXCore.ini list get higher priority

			if((tg_lookup(GID, i) < tg_lookup(repeater[i].busy_tg, i)) && (strt_packet==1)&&(repeater[i].tx_busy==1))
			{
				repeater[i].busy_tg = GID;
				std::cout << ctime(&tm) << "Overriding TG: " << repeater[i].busy_tg << " with  TG: " << GID << " on Repeater " << i << std::endl;
			}

			// Next, if repeater is considered busy, only send the talkgroup it has been assigned

			if((repeater[i].tx_busy == 1) && (repeater[i].busy_tg!=GID))
			{
				std::cout << ctime(&tm) << " Repeater " << i << " not geting " << GID << "due to active TX on " << repeater[i].busy_tg << std::endl;
				continue;	
			}


			if(strt_packet ==1)
			{
				rpton_64001(i);
				usleep(50000);
				rpton_64001(i);
				usleep(50000);
				repeater[i].tx_busy = 1;
				repeater[i].busy_tg = GID;
			}
			else
			{
				if(++repeater[i].vp_count > 2)
					rpton_64001(i);
			}	

			// Need to rewrite IP address for len 47 and 59 packets it is 8,9,10,11
			buf[8] = (char)tempaddr >> 24;
			buf[9] = (char)(tempaddr >> 16) & 0xff;
			buf[10] = (char)(tempaddr >> 8) & 0xff;
			buf[11] = (char)tempaddr & 0xff;

			std::cout << ctime(&tm) << "Sending size " << recvlen << " packet to Repeater " << i << " with TG: " << GID << std::endl;
			sendto(socket_00, buf, recvlen, 0, (struct sockaddr *)&repeater[i].rpt_addr_00,
		 		sizeof(repeater[i].rpt_addr_00));

			repeater[i].time_since_tx = 0;

			if(repeater[rpt_id].rx_activity == 0)
			{		
				shutdown_64001(i);
			}
		}
				
	}
}

int tg_lookup(int GID, int i)
{
	int j;

	j = 0;

	while (repeater[i].tg_list[j] != 0)
	{
		if (repeater[i].tg_list[j++] == GID)
			return(j-1);
	}
	return(-1);
}

void *timing_thread(void *t_id)
{
	int i;
	unsigned int seconds = 0;
	struct addrinfo hints, *result;
	char h_buf[59];
	char nx_packet[28] = { 0x00, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x4e, 0x58, 0x44, 0x4e, 0x4e, 0x31, 0x58, 0x44,
				 0x4e, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00 };
	

	
	
        memset((char *)&h_buf[0], 0, sizeof(h_buf));
	for(;;)
	{
		for( i = 0; i < repeater_count; i++)
		{
			repeater[i].time_since_rx++;
			if(repeater[i].time_since_rx > repeater[i].hold_time)
				repeater[i].time_since_rx = repeater[i].hold_time;

			repeater[i].time_since_tx++;
		
			if(repeater[i].time_since_tx > repeater[i].tx_hold_time)
			{
				repeater[i].time_since_tx = repeater[i].tx_hold_time;
				repeater[i].tx_busy = 0;
			}
		}	
	
		if((++seconds % 20) == 0 )
		{
			for( i = 0; i < repeater_count; i++)
				{
					if ( repeater[i].stealth )
					{
						sendto(socket_00, h_buf, sizeof(h_buf), 0, (struct sockaddr *)&repeater[i].rpt_addr_00,
							sizeof(repeater[i].rpt_addr_00));
						sendto(socket_01, nx_packet, sizeof(nx_packet), 0, (struct sockaddr *)&repeater[i].rpt_addr_01,
							sizeof(repeater[i].rpt_addr_01));
					}	
				}

		}	

		if(seconds % 900 == 0)

		{
			memset(&hints,0, sizeof(hints));
			hints.ai_family = AF_INET;

			if(getaddrinfo(repeater[i].hostname, NULL, &hints, &result) == 0)
			{
				repeater[i].rpt_addr_00.sin_addr.s_addr = ((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr;
				repeater[i].rpt_addr_01.sin_addr.s_addr = ((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr;
			}

		}

		sleep(1);
	}

	
}


// 64001 sequence, must send every 0.2seconds

void rpton_64001(int rpt_no)
{
		up_packet[24] = (char)repeater[rpt_no].ran;
		sendto(socket_01, up_packet, sizeof(up_packet), 0, (struct sockaddr *)&repeater[rpt_no].rpt_addr_01,
		 	sizeof(repeater[rpt_no].rpt_addr_01));
		repeater[rpt_no].vp_count = 0;
}

// Shutdown sequence to key down repeater

void shutdown_64001(int rpt_no)
{
	down_packet[12] = (char)(repeater[rpt_no].uid >> 8);
	down_packet[13] = (char)repeater[rpt_no].uid & 0xff;

	usleep(200000);
	sendto(socket_01, down_packet, sizeof(down_packet), 0, (struct sockaddr *)&repeater[rpt_no].rpt_addr_01,
		 sizeof(repeater[rpt_no].rpt_addr_01));

	usleep(200000);

	sendto(socket_01, down_packet, sizeof(down_packet), 0, (struct sockaddr *)&repeater[rpt_no].rpt_addr_01,
		 sizeof(repeater[rpt_no].rpt_addr_01));

	usleep(200000);

	sendto(socket_01, down_packet, sizeof(down_packet), 0, (struct sockaddr *)&repeater[rpt_no].rpt_addr_01,
		 sizeof(repeater[rpt_no].rpt_addr_01));

}


int main(int argc, char *argv[])
{
	int i, j, k;
	struct addrinfo hints, *result;

	boost::property_tree::ptree pt;

	try {

	boost::property_tree::ini_parser::read_ini("NXCore.ini", pt);

	}
	catch(const boost::property_tree::ptree_error  &e)
	{
		std::cout << "Config file not found!" << std::endl << std::endl;
		exit(1);
	}


	// Print out version and copyright info
	std::cout << version << std::endl;
	std::cout << copyright << std::endl << std::endl;

	// Get list of repeaters

	std::string s = pt.get<std::string>("repeaters");
	std::string tg;

	std::vector<std::string> elems;
	std::vector<std::string> tg_elems;

	// Split by space or tab
	boost::split(elems, s, boost::is_any_of("\t ,"), boost::token_compress_on);

	repeater_count = elems.size();
	std::cout << "Repeater Count:  " << repeater_count << std::endl << std::endl;

	repeater = (struct rpt *)calloc(repeater_count, sizeof(struct rpt));

	tempaddr = inet_addr(pt.get<std::string>("nodeip").c_str());

	up_packet[4] = (tempaddr << 24);
	up_packet[5] = (tempaddr << 16) & 0xff;
	up_packet[6] = (tempaddr << 8) & 0xff;
	up_packet[7] = (tempaddr & 0xff);

	down_packet[4] = (tempaddr << 24);
	down_packet[5] = (tempaddr << 16) & 0xff;
	down_packet[6] = (tempaddr << 8) & 0xff;
	down_packet[7] = (tempaddr & 0xff);


	// Start populating structure
	std::string key;

	for(i = 0; i < elems.size(); i++)
	{

		key.assign(elems[i]);
		key.append(".address");

		memset(&hints,0, sizeof(hints));
		hints.ai_family = AF_INET;

		repeater[i].hostname = (char *)pt.get<std::string>(key).c_str();
		if(getaddrinfo(repeater[i].hostname, NULL, &hints, &result) == -1)
		{
			std::cout << "Error resolving " << pt.get<std::string>(key) << ", exiting" << std::endl;
			exit(1);
		}	
	
		repeater[i].rpt_addr_00.sin_addr.s_addr = ((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr;
		repeater[i].rpt_addr_01.sin_addr.s_addr = ((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr;
		repeater[i].rpt_addr_00.sin_family = AF_INET;
		repeater[i].rpt_addr_01.sin_family = AF_INET;
		repeater[i].rpt_addr_00.sin_port = htons(64000);
		repeater[i].rpt_addr_01.sin_port = htons(64001);

		std::cout << "Repeater " << i << " address: " << inet_ntoa(repeater[i].rpt_addr_00.sin_addr) << std::endl << std::endl;
		// Parse out the talkgroups

		key.assign(elems[i]);
		key.append(".tg_list");
		tg = pt.get<std::string>(key).c_str();

		boost::split(tg_elems, tg, boost::is_any_of("\t ,"), boost::token_compress_on);
	
		repeater[i].tg_list = (unsigned int *)calloc(tg_elems.size()+1,sizeof(int));
		std::cout << "Talkgroups " << tg_elems.size() << std::endl; 
		std::cout << "Repeater " << i << "  Talkgroups: ";

		for(j = 0; j < tg_elems.size(); j++)
		{
			repeater[i].tg_list[j] = atoi(tg_elems[j].c_str());
			std::cout << " " << repeater[i].tg_list[j];

		}
		std::cout << std::endl << std::endl;
		repeater[i].ran = pt.get<int>(elems[i] + ".ran");
		repeater[i].hold_time = pt.get<int>(elems[i] + ".rx_hold_time");
		repeater[i].time_since_rx = repeater[i].hold_time;
		repeater[i].stealth = pt.get<int>(elems[i] + ".stealth");
		repeater[i].tx_hold_time = pt.get<int>(elems[i] + ".tx_hold_time");
		repeater[i].time_since_tx = repeater[i].tx_hold_time;

	}


	// start the thread


	pthread_t l_thread;
	pthread_t t_thread;

	if(pthread_create(&l_thread, NULL, listen_thread, (void *)0))  {
		fprintf(stderr, "Problem creating thread.  Exiting\n");
		return 1; 
	}
	
	if(pthread_create(&t_thread, NULL, timing_thread, (void *)0))  {
		fprintf(stderr, "Problem creating thread.  Exiting\n");
		return 1; 
	}

	while(1==1)
	{
		sleep(1);
	}
	pthread_exit(NULL);
}
