/*How this works:
  This code is designed for FPGA-based network data processing. It consists of four components:
  
  1.byteSwap16: A utility function that swaps bytes in a 16-bit input, used for handling endianess in network communications.
  
  2.ethernet_remover: This function processes incoming packets, removing the Ethernet header from non-ARP packets while forwarding 
  ARP packets unchanged. It employs a state machine to manage different stages of packet processing, including checking for packet 
  types and handling packet forwarding or Ethernet header removal as appropriate.
  
  3. packet_identification: It identifies the type and protocol of incoming packets, assigning them a specific destination identifier
  based on their Ethernet type (e.g., ARP, IPv4) and IP protocol (e.g., ICMP, TCP, UDP). This function decides whether a packet should 
  be forwarded, dropped, or further processed based on its content.
  
  4.packet_handler: The main orchestrator that uses packet_identification to classify packets and then directs them to ethernet_remover 
  for Ethernet header stripping when necessary. Processed packets are then output for further handling.*/

#include "packet_handler.hpp"

/*This utility function swaps the bytes of a 16-bit input vector. It's commonly used in network applications 
  where endianess conversion is necessary due to the difference in byte order between network order (big-endian)
  and host order (little-endian or big-endian depending on the architecture).*/

ap_uint<16> byteSwap16(ap_uint<16> inputVector) {
	return (inputVector.range(7,0), inputVector(15, 8));
}

/*This function removes the Ethernet header from incoming packets (dataIn) and forwards the rest of the packet data 
  to the output stream (dataOut). It has a state machine with four states:

  FIRST_WORD: Checks the first word of the incoming packet. If the packet is an ARP packet (indicated with dest == 0), 
  it forwards the packet as-is. Otherwise, it strips the Ethernet header and prepares the packet for forwarding.
  
  FWD: Forwards ARP packets without modification.
  
  REMOVING: Removes the Ethernet header from non-ARP packets.
  
  EXTRA: Handles any remaining data bits that need to be forwarded after the main packet data has been processed.
  
  This function ensures that ARP packets are passed through without modification, while other packets have their Ethernet 
  headers removed before being forwarded.*/

void ethernet_remover (			
			stream<axiWordOut>&			dataIn,
			stream<axiWordOut>&			dataOut) {

#pragma HLS PIPELINE II=1

	enum er_states {FIRST_WORD , FWD , REMOVING, EXTRA};
	static er_states er_fsm_state = FIRST_WORD;

	axiWordOut 			currWord;
	axiWordOut 			sendWord;
	static axiWordOut 	prevWord;

	switch (er_fsm_state){
		case FIRST_WORD:
			if (!dataIn.empty()){
				dataIn.read(currWord);
				
				if (currWord.dest == 0){			// ARP packets must remain intact
					sendWord = currWord;
					er_fsm_state 	= FWD;
				}
				else{								// No ARP packet, Re arrange the order in the output word
					sendWord.data(511,400) 	=  0;
					sendWord.keep( 63, 50) 	=  0;
					sendWord.data(399,  0) 	=  currWord.data (511,112);
					sendWord.keep( 49,  0) 	=  currWord.keep ( 63, 14);
					sendWord.dest 			=  currWord.dest;
					sendWord.last 			=  1;
					er_fsm_state 	= REMOVING;
				}

				if (currWord.last){				// If the packet is short stay in this state
					dataOut.write(sendWord);
					er_fsm_state = FIRST_WORD;
				}
				else if (currWord.dest == 0){	// ARP packets
					dataOut.write(sendWord);
				}

				prevWord = currWord;
			}
			break;
		case FWD:
			if (!dataIn.empty()){
				dataIn.read(currWord);
				if (currWord.last){
					er_fsm_state = FIRST_WORD;
				}
				dataOut.write(currWord);
			}
			break;
		case REMOVING:
			if (!dataIn.empty()){
				dataIn.read(currWord);

				sendWord.data(399,  0) 	=  prevWord.data(511,112);
				sendWord.keep( 49,  0) 	=  prevWord.keep( 63, 14);
				sendWord.data(511,400) 	=  currWord.data(111,  0);
				sendWord.keep( 63, 50) 	=  currWord.keep( 13,  0);
				sendWord.dest 			=  prevWord.dest;

				if (currWord.last){
					if (currWord.keep.bit(14)){							// When the input packet ends we have to check if all the input data
						er_fsm_state = EXTRA;							// was sent, if not an extra transaction is needed, but for the current
						sendWord.last 			=  0;					// transaction tlast must be 0
					}
					else {
						sendWord.last 			=  1;
						er_fsm_state = FIRST_WORD;
					}
				}
				else {
					sendWord.last 			=  0;
				}

				prevWord = currWord;
				dataOut.write(sendWord);
			}
			break;
		case EXTRA:
			sendWord.data(511,400) 	=  0;								// Send the remaining piece of information
			sendWord.keep( 63, 50) 	=  0;
			sendWord.data(399,  0) 	=  prevWord.data(511,112);
			sendWord.keep( 49,  0) 	=  prevWord.keep( 63, 14);
			sendWord.dest 			=  prevWord.dest;
			sendWord.last 			=  1;
			dataOut.write(sendWord);
			er_fsm_state = FIRST_WORD;
			break;
	}

}

/*This function identifies packets based on their Ethernet type and IP protocol, marking them for different processing paths. 
  It uses a state machine with three states:

  FIRST_WORD: Reads the first word of each incoming packet to determine its type (ARP, IPv4, etc.) and protocol (ICMP, TCP, UDP). 
  Based on this information, it assigns a destination identifier (dest) to the packet.
  
  FWD: Forwards the packet to the output stream with the assigned dest.
  
  DROP: Discards packets that do not match the criteria for forwarding.

  This function categorizes packets for subsequent processing based on their Ethernet type and IP protocol.*/

void packet_identification(
			stream<axiWordIn>&			dataIn,
			stream<axiWordOut>&			dataOut) {


#pragma HLS PIPELINE II=1


	enum pi_states {FIRST_WORD , FWD ,DROP};
	static pi_states pi_fsm_state = FIRST_WORD;
	static dest_type tdest_r;
	
	dest_type tdest;
	axiWordIn 	currWord;
	axiWordOut 	sendWord;
	ap_uint<16>	ethernetType;
	ap_uint<4>	ipVersion;
	ap_uint<8>	ipProtocol;
	bool		forward = true;

	switch (pi_fsm_state) {
		case FIRST_WORD :
			if (!dataIn.empty()){
				dataIn.read(currWord);
				ethernetType = byteSwap16(currWord.data(111,96));		// Get Ethernet type
				ipVersion    = currWord.data(119,116);					// Get IPv4
				ipProtocol   = currWord.data(191,184);					// Get protocol for IPv4 packets

				if (ethernetType == TYPE_ARP){
					tdest = 0;
					sendWord.dest = 0;
				}
				else if (ethernetType == TYPE_IPV4){
					if (ipVersion == 4){ 	// Double check
						if (ipProtocol == PROTO_ICMP ){
							tdest = 1;
						}
						else if (ipProtocol == PROTO_TCP ){
							tdest = 2;
						}
						else if (ipProtocol == PROTO_UDP ){
							tdest = 3;
						}
						else {
							forward = false;
						}
					}
				}
				else {
					forward = false;
				}

				sendWord.data = currWord.data;
				sendWord.keep = currWord.keep;
				sendWord.last = currWord.last;
				sendWord.dest = tdest;										// Compose output word
				
				tdest_r 		= tdest;	// Save tdest

				if (forward){												// Evaluate if the packet has to be send or dropped
					dataOut.write(sendWord);
					pi_fsm_state = FWD;
				}
				else {
					pi_fsm_state = DROP;
				}

				if (currWord.last){
					pi_fsm_state = FIRST_WORD;
				}
			}
			break;
		case FWD :
			if (!dataIn.empty()){
				dataIn.read(currWord);
				
				sendWord.data = currWord.data;
				sendWord.keep = currWord.keep;
				sendWord.last = currWord.last;
				sendWord.dest = tdest_r;
				dataOut.write(sendWord);
				
				if (currWord.last){											// Keep sending the packet until ends
					 pi_fsm_state = FIRST_WORD;
				}
			}
			break;
		case DROP :
			if (!dataIn.empty()){
				dataIn.read(currWord);
				if (currWord.last){											// Dropping the packet until ends
					 pi_fsm_state = FIRST_WORD;
			}
			break;
		}
	}	
}

/*The main function orchestrates the packet processing flow. It takes incoming packets (dataIn), identifies them using 
  packet_identification, and then either forwards or removes their Ethernet headers using ethernet_remover. The processed 
  packets are then output through dataOut.

  The use of #pragma HLS directives suggests that this code is intended for synthesis with an HLS tool, targeting FPGA 
  deployment. These directives control various aspects of the synthesis process, such as inlining decisions, interface generation, 
  and pipeline initiation intervals, to optimize the hardware implementation.*/
  
void packet_handler(
			stream<axiWordIn>&			dataIn,
			stream<axiWordOut>&			dataOut) {

#pragma HLS INTERFACE ap_ctrl_none port=return
#pragma HLS DATAFLOW

#pragma HLS INTERFACE axis register both port=dataIn name=s_axis
#pragma HLS INTERFACE axis register both port=dataOut name=m_axis

	static stream<axiWordOut>     eth_level_pkt("eth_level_pkt");
	#pragma HLS STREAM variable=eth_level_pkt depth=16
	#pragma HLS DATA_PACK variable=eth_level_pkt

	packet_identification(
			dataIn,
			eth_level_pkt); 

	ethernet_remover (			
			eth_level_pkt,
			dataOut);

}
