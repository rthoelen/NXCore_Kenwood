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
#include <unistd.h>

char version[] = "NXCORE Manager, Kenwood, version 1.2";
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
	unsigned char tx_ran;	
	unsigned char rx_ran;	
	unsigned int active_tg; // talkgroup currently active
	unsigned int last_tg;  // used for talk group hold time
	unsigned int *tg_list;   // if a talkgroup isn't in this list, it isn't repeated
	unsigned int *tac_list;   // Tactical talkgroups (only comes through if received) 
	int uid; // need this for Kenwood udp 64001 data
	int tx_uid; // UID on repeater transmitting
	int tx_otaa;
	int keydown;

} *repeater;


// RAN is at up_packet[24]

char up_packet[28] = { 0x8a, 0xcc, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, \
			0x4b, 0x57, 0x4e, 0x45, 0x00, 0x00, 0x00, 0x00, \
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, \
			0x00, 0x00, 0x00, 0x00 };

char down_packet[20] = { 0x8b, 0xcc, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, \
			0x4b, 0x57, 0x4e, 0x45, 0x00, 0x00, 0x00, 0x00, \
			0x01, 0x00, 0x00, 0x00 };


void rpton_64001(int);
void shutdown_64001(void);
void snd_packet(unsigned char [], int, int,int, int);
int tg_lookup(int, int);
int tac_lookup(int, int);

int repeater_count;

int debug = 0;

std::vector<std::string> r_list;

unsigned int tempaddr;

int packet_send_flag;
useconds_t tx_delay;

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
	int GID, UID, RAN;

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
		strt_packet = 0;
                if (recvlen == 47) {


                        buf[recvlen] = 0;
			rpt_id = get_repeater_id(&remaddr);


			if (rpt_id == -1)
			{
				std::cout << " Unauthorized repeater, "
					<< inet_ntoa(remaddr.sin_addr)
					<< ", dropping packet" << std::endl;

				continue;  // Throw out packet, not in our list
			}

			buf[8] = (repeater[rpt_id].rpt_addr_00.sin_addr.s_addr) >> 24;
			buf[9] = ((repeater[rpt_id].rpt_addr_00.sin_addr.s_addr) >> 16) & 0xff;
			buf[10] = ((repeater[rpt_id].rpt_addr_00.sin_addr.s_addr) >> 8) & 0xff;
			buf[11] = (repeater[rpt_id].rpt_addr_00.sin_addr.s_addr) & 0xff;

			// This packet is getting in the way. Block it

			if((buf[20] == 0x0a) && (buf[21] == 0x05) &&
				(buf[22] == 0x0a) && (buf[23] == 0x10) &&
					(buf[28] == 0x10))
			{
				continue;
			}		


			// This would be a start packet
			if((buf[20] == 0x0a) && (buf[21] == 0x05) &&
				(buf[22] == 0x0a) && (buf[23] == 0x10) &&
					(buf[28] == 0x01))
			{
				GID = (buf[31] << 8) + buf[34];
				UID = (buf[29] << 8) + buf[32];
				RAN = buf[24];

				if ((UID==0) && (GID==0))
					continue;

				if (RAN != repeater[rpt_id].rx_ran)
				{
					if(debug)
						std::cout << "Repeater  ->" << r_list[rpt_id]
							<< "<-  not passing start from UID: " << UID
							<< " from TG: " << GID
							<< " because RAN: " << RAN
							<< " isn't the correct receive RAN" << std::endl;

					sendto(socket_00, buf, recvlen, 0, (struct sockaddr *)&tport,
		 				sizeof(tport));

					// Special case: if no talkgroup and different RAN, assume local
					// and block network activity

					if (GID == 0)
					{
						repeater[rpt_id].rx_activity = 1;
						repeater[rpt_id].time_since_rx = 0;
						repeater[rpt_id].active_tg = GID;
					}
						
					continue;
				}

				repeater[rpt_id].rx_activity = 1;
				repeater[rpt_id].active_tg = GID;
				repeater[rpt_id].busy_tg = GID;
				repeater[rpt_id].uid = UID;
				strt_packet = 1;

				std::cout << "Repeater  ->" << r_list[rpt_id]
					<< "<-  receiving start from UID: " << UID
					<< " from TG: " << GID
					<< " on RAN: " << RAN << std::endl;

				repeater[rpt_id].time_since_rx = 0;
			}
		
			// End, sent shutdown on 64001	
			if((buf[20] == 0x0a) && (buf[21] == 0x05) &&
				(buf[22] == 0x0a) && (buf[23] == 0x10) &&
					(buf[28] == 0x08))
			{
				GID = (buf[31] << 8) + buf[34];
				UID = (buf[29] << 8) + buf[32];
				RAN = buf[24];
				if ((UID==0) && (GID==0))
					continue;
				if (UID == 0x36AF)
					continue;
				if (RAN != repeater[rpt_id].rx_ran)
				{
					if(debug)
						std::cout << "Repeater  ->" << r_list[rpt_id]
							<< "<-  not passing stop from UID: " << UID
							<< " from TG: " << GID
							<< " because RAN: " << RAN
							<< " isn't the correct receive RAN" << std::endl;

					sendto(socket_00, buf, recvlen, 0, (struct sockaddr *)&tport,
		 				sizeof(tport));

					// Special case: if no talkgroup and different RAN, assume local
					// and block network activity

					if (GID == 0)
					{
						repeater[rpt_id].rx_activity = 0;
						repeater[rpt_id].time_since_rx = 0;
						repeater[rpt_id].active_tg = GID;
						repeater[rpt_id].last_tg = repeater[rpt_id].active_tg;
					}
					continue;
				}

				repeater[rpt_id].rx_activity = 0;    // Activity on channel is over
				repeater[rpt_id].last_tg = repeater[rpt_id].active_tg;
	
				repeater[rpt_id].time_since_rx = 0;
				std::cout << "Repeater  ->" << r_list[rpt_id]
					<< "<-  receiving stop from UID: " << UID
					<< " from TG: " << GID << std::endl;
			}	
				
			// Need to put GID back if not a start packet

			GID = repeater[rpt_id].active_tg;

			// send packet to repeaters

			while(packet_send_flag !=1)
			{
				usleep(5000);
			}


			sendto(socket_00, buf, recvlen, 0, (struct sockaddr *)&tport,
		 		sizeof(tport));
			snd_packet(buf, recvlen, GID, rpt_id, strt_packet);

				
		}
                
		if (recvlen == 59) {

			rpt_id = get_repeater_id(&remaddr);
			if (rpt_id == -1)
			{
				if(debug)
					std::cout << "Unauthorized repeater, " 
						<< inet_ntoa(remaddr.sin_addr) 
						<< ", dropping packet" << std::endl;

				continue;  // Throw out packet, not in our list
			}	

			// Heartbeat packet from another repeater, bounce back
			// but then continue 
			if ((buf[0] == 0x00) && (buf[1] == 0x00))
			{
				
				sendto(socket_00, buf, recvlen, 0, (struct sockaddr *)&repeater[rpt_id].rpt_addr_00,
		 			sizeof(repeater[rpt_id].rpt_addr_00));
				continue; 
			}

			if (repeater[rpt_id].rx_activity == 0)
			{
				if(debug)
					std::cout << "Not sending vocoder packet from Repeater " 
						<< rpt_id << " due to rx_flag not set" << std::endl;

				continue;
			}


			repeater[rpt_id].time_since_rx = 0;	
			GID = repeater[rpt_id].active_tg;

			while(packet_send_flag !=1)
			{
				usleep(5000);
			}
			// send packet to repeaters that can receive it


			sendto(socket_00, buf, recvlen, 0, (struct sockaddr *)&tport,
		 		sizeof(tport));
			snd_packet(buf, recvlen, GID, rpt_id, 0);
		}
		
        }	
}


void snd_packet(unsigned char buf[], int recvlen, int GID, int rpt_id, int strt_packet)
{
	int i, j;
	int tg;
	int tac_flag;
	in_addr_t tmp_addr;


	// This blocks talkgroups received on a repeater that don't match
	// the talkgroup list

	if (tg_lookup(GID, rpt_id) == -1)
	{
		if(debug)
			std::cout << "Repeater  ->" << r_list[rpt_id] 
			<< "<-  blocked, unauthorized talkgroup" 
			<< GID << std::endl;

		return;
	}


	// Sending selection logic

	for(i = 0; i < repeater_count; i++)
	{
	
		// Don't reflect our own packets back

		if (rpt_id == i)
			continue;

		// Block OTAA if needed

		if((buf[20] == 0x0a) && (buf[21] == 0x05) && (buf[22] == 0x0a) &&
			 ((buf[23] == 0x01) || (buf[23] == 0x80)) &&
				(repeater[i].tx_otaa == 0))
		{
			continue;
		}

		// Get the flag from the Tactical group list
		tac_flag = tac_lookup(GID, i);

		// Is the talkgroup being sent in this repeater's list? If not, stop here

		tg = tg_lookup(GID, i);
		if (tg != -1)

		{		
		

			// Process TAC groups first
			// The only way to let the TAC group(s) through is if the RX active group matches
	

			if(tac_flag != -1)
			{
				if((repeater[i].time_since_rx == repeater[i].hold_time) || (repeater[i].active_tg != GID))
					continue;
			}

			// Do not send packets to the repeater if it is receiving

			if(repeater[i].rx_activity == 1)
				continue;

			// First, if this particular repeater just had RX activity, if the packet 
			// doesn't match the last talkgroup, drop it.  This should solve most contention
			// issues

			if((repeater[i].last_tg != GID) && (tac_flag == -1))
			{
				if(repeater[i].time_since_rx < repeater[i].hold_time)
				{
					if(debug)
						std::cout << "Blocking TG: " << GID 
							<< " sent on Repeater  ->" << r_list[i]
							<< "<-  due to recent RX on TG: " 
							<< repeater[i].last_tg << std::endl;

					continue;
				}
			}


			// Next, we need to determine if we need to preempt a talkgroup
			// Talkgroups that are on the left in the NXCore.ini list get higher priority

			if((tg_lookup(GID, i) < tg_lookup(repeater[i].busy_tg, i)) && (strt_packet==1)&&(repeater[i].tx_busy==1) &&
				(tac_flag == -1))
			{
				repeater[i].busy_tg = GID;

				if(debug)
					std::cout << "Overriding TG: " << repeater[i].busy_tg 
						<< " with  TG: " << GID 
						<< " on Repeater  ->" << r_list[i] << std::endl;
			}

			// Next, if repeater is considered busy, only send the talkgroup it has been assigned

			if((repeater[i].tx_busy == 1) && (repeater[i].busy_tg!=GID) && (tac_flag == -1))
			{
				if(debug)
					std::cout << " Repeater  ->" << r_list[i] << "<-  not geting " 
						<< GID << "due to active TX on " 
						<< repeater[i].busy_tg << std::endl;

				continue;	
			}


			if(strt_packet ==1)
			{
				rpton_64001(i);
				usleep(20000);
				repeater[i].tx_busy = 1;
				repeater[i].busy_tg = GID;
				repeater[i].vp_count = 0;
			}
			else
			{
				if(++repeater[i].vp_count > 3)
					rpton_64001(i);
			}	

			// Need to rewrite IP address for len 47 and 59 packets it is 8,9,10,11
			buf[8] = (char)(tempaddr >> 24) & 0xff;
			buf[9] = (char)(tempaddr >> 16) & 0xff;
			buf[10] = (char)(tempaddr >> 8) & 0xff;
			buf[11] = (char)tempaddr & 0xff;

			if(recvlen == 47)
			{
				buf[24] = repeater[i].tx_ran;
			}

			repeater[i].tx_uid = repeater[rpt_id].uid;

			if(debug)
				std::cout << "Sending datagram to repeater  ->" << r_list[i] << std::endl;

			sendto(socket_00, buf, recvlen, 0, (struct sockaddr *)&repeater[i].rpt_addr_00,
		 		sizeof(repeater[i].rpt_addr_00));


			repeater[i].time_since_tx = 0;

			if(repeater[rpt_id].rx_activity == 0)
			{		
				repeater[i].keydown=1;
			}
		}
				
	}
	packet_send_flag = 0;

	if(repeater[rpt_id].rx_activity == 0)
	{		
		shutdown_64001();
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

int tac_lookup(int GID, int i)
{
	int j;

	j = 0;

	while (repeater[i].tac_list[j] != 0)
	{
		if (repeater[i].tac_list[j++] == GID)
			return(j-1);
	}
	return(-1);
}

// This timing thread will hopefully even out packets that
// arrive a bit too soon.  The delay is tunable in case
// a shorter/longer time works better.

void *ptiming_thread(void *t_id)
{
	for(;;)
	{
		usleep(tx_delay);
		packet_send_flag = 1;
	}

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
	h_buf[21] = 0x99;
	for(;;)
	{
		for( i = 0; i < repeater_count; i++)
		{
			repeater[i].time_since_rx++;
			if(repeater[i].time_since_rx > repeater[i].hold_time)
			{
				repeater[i].time_since_rx = repeater[i].hold_time;
				repeater[i].rx_activity = 0;
			}

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

		sleep(1);
	}

	
}


// 64001 sequence, must send every 0.2seconds

void rpton_64001(int rpt_no)
{
		up_packet[24] = (char)repeater[rpt_no].tx_ran;
		sendto(socket_01, up_packet, sizeof(up_packet), 0, (struct sockaddr *)&repeater[rpt_no].rpt_addr_01,
		 	sizeof(repeater[rpt_no].rpt_addr_01));
		repeater[rpt_no].vp_count = 0;
}

// Shutdown sequence to key down repeater

void shutdown_64001(void)
{

	int i,j;


	usleep(25000);
	for(i = 0; i < 3; i++)
	{	
		for(j = 0; j < repeater_count; j++)
		{
			if(repeater[j].keydown == 1)
			{
				down_packet[12] = (char)(repeater[j].tx_uid >> 8);
				down_packet[13] = (char)repeater[j].tx_uid & 0xff;
				sendto(socket_01, down_packet, sizeof(down_packet), 0, (struct sockaddr *)&repeater[j].rpt_addr_01,
					sizeof(repeater[j].rpt_addr_01));

			}
		}
		usleep(200000);
	}

	for(j = 0; j < repeater_count; j++)
		repeater[j].keydown = 0;

}

void write_map(char *mfile)
{
	int i;

	std::ofstream out(mfile);

	// Write the preamble

	out << " var json1 = [ " << std::endl;

	for( i = 0; i < repeater_count; i++)
	{
		out << " { " << std::endl;
		// Determine what state we are in:

		// Green: IDLE
		// Red: TX
		// Blue: RX

		if (repeater[i].rx_activity == 1)
		{
			out << "\"icon\" : \"http://maps.google.com/mapfiles/ms/icons/blue-dot.png\"," << std::endl;
		
			out << "\"contentstr\" : \"<p>RX TG: <b>" 
				<< repeater[i].active_tg << "</b><br/>RX Timer: <b>" 
				<< repeater[i].time_since_rx << "<b/><br/>UID: <b>" 
				<< repeater[i].uid << "</b></p>\" " << std::endl;

			out << " }," << std::endl;
			continue;

		}			

		if ((repeater[i].rx_activity == 0)&&(repeater[i].tx_busy == 0))
		{
			out << "\"icon\" : \"http://maps.google.com/mapfiles/ms/icons/green-dot.png\"," << std::endl;
		
			out << "\"contentstr\" : \"<p>Repeater IDLE</p>\"  " << std::endl;
			out << " }," << std::endl;
			continue;
		}

		if (repeater[i].tx_busy == 1)
		{

			out << "\"icon\" : \"http://maps.google.com/mapfiles/ms/icons/red-dot.png\"," << std::endl;
		
			out << "\"contentstr\" : \"<p>TX TG: <b>" << repeater[i].busy_tg 
				<< "</b><br/>TX Timer: <b>" << repeater[i].time_since_tx 
				<< "<br/><b/>UID: <b>" << repeater[i].tx_uid << "</b></p>\" " << std::endl;

			out << " }," << std::endl;
			continue;


		}

	}
	out << " ];" << std::endl;

	out.close();

	
}

	


int main(int argc, char *argv[])
{
	int i, j, len;
	struct addrinfo hints, *result;
	char *mapfile;
	std::string mfile;
	int mapflag;

	boost::property_tree::ptree pt;

	try {

	boost::property_tree::ini_parser::read_ini("NXCore.ini", pt);

	}
	catch(const boost::property_tree::ptree_error  &e)
	{
		std::cout << "Config file not found!" << std::endl << std::endl;
		exit(1);
	}


	if(argc > 1)
		if (strcmp(argv[1], "-d") == 0)
			debug = 1;

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

	r_list = elems;

	repeater = (struct rpt *)calloc(repeater_count, sizeof(struct rpt));

	tx_delay = 1000 * pt.get<int>("tx_delay_msec");


	// Check for if we need to output a JSON file for Google Maps

	try {
	mfile = pt.get<std::string>("mapfile");
	}
	catch(const boost::property_tree::ptree_error  &e)
	{
		std::cout << "mapfile= property not found in NXCore.ini" << std::endl << std::endl;
		exit(1);
	}


	if(mfile.size() !=0)
	{
		std::cout << "Turning on map data" << std::endl << std::endl;
		mapfile = (char *)calloc(1,mfile.size()+1);
		memcpy(mapfile, (char *)mfile.c_str(),mfile.size()+1);
		mapflag = 1;
	}
	else
	{
		std::cout << "Map data turned off" << std::endl << std::endl;
		mapflag = 0;
	}

	tempaddr = inet_addr(pt.get<std::string>("nodeip").c_str());

	up_packet[4] = (tempaddr >> 24);
	up_packet[5] = (tempaddr >> 16) & 0xff;
	up_packet[6] = (tempaddr >> 8) & 0xff;
	up_packet[7] = (tempaddr & 0xff);

	down_packet[4] = (tempaddr >> 24);
	down_packet[5] = (tempaddr >> 16) & 0xff;
	down_packet[6] = (tempaddr >> 8) & 0xff;
	down_packet[7] = (tempaddr & 0xff);


	// Start populating structure
	std::string key;

	for(i = 0; i < elems.size(); i++)
	{

		key.assign(elems[i]);
		key.append(".address");

		memset(&hints,0, sizeof(hints));
		hints.ai_family = AF_INET;

		
		len = pt.get<std::string>(key).size();
		repeater[i].hostname = (char *)calloc(1, len+1);
		memcpy(repeater[i].hostname, (char *)pt.get<std::string>(key).c_str(),len+1);

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
		
		std::cout << std::endl << std::endl;
		std::cout << "Repeater " << r_list[i] << " address: " 
			<< inet_ntoa(repeater[i].rpt_addr_00.sin_addr) << std::endl << std::endl;

		// Parse out the talkgroups

		key.assign(elems[i]);
		key.append(".tg_list");
		tg = pt.get<std::string>(key).c_str();

		boost::split(tg_elems, tg, boost::is_any_of("\t ,"), boost::token_compress_on);
	
		repeater[i].tg_list = (unsigned int *)calloc(tg_elems.size()+1,sizeof(int));
		std::cout << "Talkgroups " << tg_elems.size() << std::endl; 
		std::cout << "Repeater " << r_list[i] << "  Talkgroups: ";

		for(j = 0; j < tg_elems.size(); j++)
		{
			repeater[i].tg_list[j] = atoi(tg_elems[j].c_str());
			std::cout << " " << repeater[i].tg_list[j];

		}
		std::cout << std::endl;

		// Do the same for the tactical list

		key.assign(elems[i]);
		key.append(".tac_list");
		tg = pt.get<std::string>(key).c_str();

		boost::split(tg_elems, tg, boost::is_any_of("\t ,"), boost::token_compress_on);
	
		repeater[i].tac_list = (unsigned int *)calloc(tg_elems.size()+1,sizeof(int));
		std::cout << "Tactical Talkgroups " << tg_elems.size() << std::endl; 
		std::cout << "Repeater " << i << "  Tactical Talkgroup List: ";

		for(j = 0; j < tg_elems.size(); j++)
		{
			repeater[i].tac_list[j] = atoi(tg_elems[j].c_str());
			std::cout << " " << repeater[i].tac_list[j];

		}


		std::cout << std::endl << std::endl;
		repeater[i].tx_ran = pt.get<int>(elems[i] + ".tx_ran");
		repeater[i].rx_ran = pt.get<int>(elems[i] + ".rx_ran");
		repeater[i].hold_time = pt.get<int>(elems[i] + ".rx_hold_time");
		repeater[i].time_since_rx = repeater[i].hold_time;
		repeater[i].stealth = pt.get<int>(elems[i] + ".stealth");
		repeater[i].tx_hold_time = pt.get<int>(elems[i] + ".tx_hold_time");
		repeater[i].time_since_tx = repeater[i].tx_hold_time;
		repeater[i].tx_otaa = pt.get<int>(elems[i] + ".tx_otaa");

	}


	// start the threads


	pthread_t l_thread;
	pthread_t t_thread;
	pthread_t pt_thread;

	if(pthread_create(&l_thread, NULL, listen_thread, (void *)0))  {
		fprintf(stderr, "Problem creating thread.  Exiting\n");
		return 1; 
	}
	
	if(pthread_create(&t_thread, NULL, timing_thread, (void *)0))  {
		fprintf(stderr, "Problem creating thread.  Exiting\n");
		return 1; 
	}

	if(pthread_create(&pt_thread, NULL, ptiming_thread, (void *)0))  {
		fprintf(stderr, "Problem creating thread.  Exiting\n");
		return 1; 
	}


	int counter = 0;


	while(1==1)
	{
	
		sleep(10);
		counter++;

		// Write out the map json data

		if(mapflag)
			write_map(mapfile);

		if (counter > 90)
		{
			for (i = 0; i < repeater_count; i++)
			{
                       		if(getaddrinfo(repeater[i].hostname, NULL, &hints, &result) == 0)
                        	{
                                	repeater[i].rpt_addr_00.sin_addr.s_addr = ((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr;
                                	repeater[i].rpt_addr_01.sin_addr.s_addr = ((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr;
                        	}
			}
		counter = 0;
		}

	}
	pthread_exit(NULL);
}
