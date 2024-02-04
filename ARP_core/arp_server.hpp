#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <math.h>
#include <hls_stream.h>
#include "ap_int.h"
#include <stdint.h>
#include "ap_axi_sdata.h"

using namespace hls;

const uint16_t 		REQUEST 		= 0x0100;
const uint16_t 		REPLY 			= 0x0200;
const ap_uint<32>	replyTimeOut 	= 65536;

const ap_uint<48> BROADCAST_MAC	= 0xFFFFFFFFFFFF;	// Broadcast MAC Address

const uint8_t 	noOfArpTableEntries	= 8;

// struct axiWord {
// 	ap_uint<64>		data;
// 	ap_uint<8>		keep;
// 	ap_uint<1>		last;
// };
typedef ap_axiu<64, 0, 0, 0> axiWord;

struct arpTableReply
{
	ap_uint<48> macAddress;
	bool		hit;
	arpTableReply() {}
	arpTableReply(ap_uint<48> macAdd, bool hit)
			:macAddress(macAdd), hit(hit) {}
};

struct arpTableEntry {
	ap_uint<48>	macAddress;
	ap_uint<32> ipAddress;
	ap_uint<1>	valid;
	arpTableEntry() {}
	arpTableEntry(ap_uint<48> newMac, ap_uint<32> newIp, ap_uint<1> newValid)
				 : macAddress(newMac), ipAddress(newIp), valid(newValid) {}
};

struct arpReplyMeta
{
  ap_uint<48>   srcMac; //rename
  ap_uint<16>   ethType;
  ap_uint<16>   hwType;
  ap_uint<16>   protoType;
  ap_uint<8>    hwLen;
  ap_uint<8>    protoLen;
  ap_uint<48>   hwAddrSrc;
  ap_uint<32>   protoAddrSrc;
  arpReplyMeta() {}
};

struct rtlMacLookupRequest {
	ap_uint<1>			source;
	ap_uint<32>			key;
	rtlMacLookupRequest() {}
	rtlMacLookupRequest(ap_uint<32> searchKey)
				:key(searchKey), source(0) {}
};

struct rtlMacUpdateRequest {
	ap_uint<1>			source;
	ap_uint<1>			op;
	ap_uint<48>			value;
	ap_uint<32>			key;

	rtlMacUpdateRequest() {}
	rtlMacUpdateRequest(ap_uint<32> key, ap_uint<48> value, ap_uint<1> op)
			:key(key), value(value), op(op), source(0) {}
};

struct rtlMacLookupReply {

	ap_uint<1>			hit;
	ap_uint<48>			value;
	rtlMacLookupReply() {}
	rtlMacLookupReply(bool hit, ap_uint<48> returnValue)
			:hit(hit), value(returnValue) {}
};

struct rtlMacUpdateReply {
	ap_uint<1>			source;
	ap_uint<1>			op;
	ap_uint<48>			value;

	rtlMacUpdateReply() {}
	rtlMacUpdateReply(ap_uint<1> op)
			:op(op), source(0) {}
	rtlMacUpdateReply(ap_uint<8> id, ap_uint<1> op)
			:value(id), op(op), source(0) {}
};

void arp_server(  stream<axiWord>&          	arpDataIn,
                  stream<ap_uint<32> >&     	macIpEncode_req,
				  stream<axiWord>&          	arpDataOut,
				  stream<arpTableReply>&    	macIpEncode_rsp,
				  stream<rtlMacLookupRequest>	&macLookup_req,
				  stream<rtlMacLookupReply>		&macLookup_resp,
				  stream<rtlMacUpdateRequest>	&macUpdate_req,
				  stream<rtlMacUpdateReply>		&macUpdate_resp,
				  ap_uint<32>	      			myIpAddress,
				  ap_uint<48>					myMacAddress);
