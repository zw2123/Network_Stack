#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>

#include <hls_stream.h>
#include "ap_int.h"
#include <stdint.h>
#include <cstdlib>

using namespace hls;
using namespace std;

#ifndef _PACKET_HANDLER_HPP_
#define _PACKET_HANDLER_HPP_

const ap_uint<16> TYPE_IPV4 	= 0x0800;
const ap_uint<16> TYPE_ARP 		= 0x0806;

const ap_uint< 8> PROTO_ICMP	=  1;
const ap_uint< 8> PROTO_TCP		=  6;
const ap_uint< 8> PROTO_UDP 	= 17;



struct axiWordIn {
	ap_uint<512>	data;
	ap_uint<64>		keep;
	ap_uint<1>		last;
};


typedef ap_uint<3>		dest_type;

struct axiWordOut {
	ap_uint<512>	data;
	ap_uint<64>		keep;
	ap_uint<1>		last;
	dest_type		dest;
};


void packet_handler(
			stream<axiWordIn>&			dataIn,
			stream<axiWordOut>&			dataOut);

#endif