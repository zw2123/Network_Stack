// ==============================================================
// Generated by Vitis HLS v2023.2.1
// Copyright 1986-2022 Xilinx, Inc. All Rights Reserved.
// Copyright 2022-2023 Advanced Micro Devices, Inc. All Rights Reserved.
// ==============================================================

`timescale 1 ns / 1 ps 

(* CORE_GENERATION_INFO="arp_server_arp_server,hls_ip_2023_2_1,{HLS_INPUT_TYPE=cxx,HLS_INPUT_FLOAT=0,HLS_INPUT_FIXED=0,HLS_INPUT_PART=xcku5p-ffvb676-2-e,HLS_INPUT_CLOCK=10.000000,HLS_INPUT_ARCH=dataflow,HLS_SYN_CLOCK=2.855125,HLS_SYN_LAT=5,HLS_SYN_TPT=1,HLS_SYN_MEM=0,HLS_SYN_DSP=0,HLS_SYN_FF=1777,HLS_SYN_LUT=1140,HLS_VERSION=2023_2_1}" *)

module arp_server (
        arpDataIn_TDATA,
        arpDataIn_TKEEP,
        arpDataIn_TSTRB,
        arpDataIn_TLAST,
        macIpEncode_req_TDATA,
        arpDataOut_TDATA,
        arpDataOut_TKEEP,
        arpDataOut_TSTRB,
        arpDataOut_TLAST,
        macIpEncode_rsp_TDATA,
        macLookup_req_TDATA,
        macLookup_resp_TDATA,
        macUpdate_req_TDATA,
        macUpdate_resp_TDATA,
        myMacAddress,
        myIpAddress,
        ap_clk,
        ap_rst_n,
        arpDataIn_TVALID,
        arpDataIn_TREADY,
        arpDataOut_TVALID,
        arpDataOut_TREADY,
        macIpEncode_req_TVALID,
        macIpEncode_req_TREADY,
        macIpEncode_rsp_TVALID,
        macIpEncode_rsp_TREADY,
        macLookup_req_TVALID,
        macLookup_req_TREADY,
        macLookup_resp_TVALID,
        macLookup_resp_TREADY,
        macUpdate_req_TVALID,
        macUpdate_req_TREADY,
        macUpdate_resp_TVALID,
        macUpdate_resp_TREADY
);


input  [63:0] arpDataIn_TDATA;
input  [7:0] arpDataIn_TKEEP;
input  [7:0] arpDataIn_TSTRB;
input  [0:0] arpDataIn_TLAST;
input  [31:0] macIpEncode_req_TDATA;
output  [63:0] arpDataOut_TDATA;
output  [7:0] arpDataOut_TKEEP;
output  [7:0] arpDataOut_TSTRB;
output  [0:0] arpDataOut_TLAST;
output  [55:0] macIpEncode_rsp_TDATA;
output  [39:0] macLookup_req_TDATA;
input  [55:0] macLookup_resp_TDATA;
output  [87:0] macUpdate_req_TDATA;
input  [55:0] macUpdate_resp_TDATA;
input  [47:0] myMacAddress;
input  [31:0] myIpAddress;
input   ap_clk;
input   ap_rst_n;
input   arpDataIn_TVALID;
output   arpDataIn_TREADY;
output   arpDataOut_TVALID;
input   arpDataOut_TREADY;
input   macIpEncode_req_TVALID;
output   macIpEncode_req_TREADY;
output   macIpEncode_rsp_TVALID;
input   macIpEncode_rsp_TREADY;
output   macLookup_req_TVALID;
input   macLookup_req_TREADY;
input   macLookup_resp_TVALID;
output   macLookup_resp_TREADY;
output   macUpdate_req_TVALID;
input   macUpdate_req_TREADY;
input   macUpdate_resp_TVALID;
output   macUpdate_resp_TREADY;

 reg    ap_rst_n_inv;
wire    entry_proc_U0_ap_start;
wire    entry_proc_U0_ap_done;
wire    entry_proc_U0_ap_continue;
wire    entry_proc_U0_ap_idle;
wire    entry_proc_U0_ap_ready;
wire   [47:0] entry_proc_U0_myMacAddress_c_din;
wire    entry_proc_U0_myMacAddress_c_write;
wire    Package_Receiver_U0_ap_start;
wire    Package_Receiver_U0_ap_done;
wire    Package_Receiver_U0_ap_continue;
wire    Package_Receiver_U0_ap_idle;
wire    Package_Receiver_U0_ap_ready;
wire   [31:0] Package_Receiver_U0_myIpAddress_c_din;
wire    Package_Receiver_U0_myIpAddress_c_write;
wire   [80:0] Package_Receiver_U0_arpTableInsertFifo_din;
wire    Package_Receiver_U0_arpTableInsertFifo_write;
wire   [191:0] Package_Receiver_U0_arpReplyMetaFifo_din;
wire    Package_Receiver_U0_arpReplyMetaFifo_write;
wire    Package_Receiver_U0_arpDataIn_TREADY;
wire    Package_Sender_U0_ap_start;
wire    Package_Sender_U0_ap_done;
wire    Package_Sender_U0_ap_continue;
wire    Package_Sender_U0_ap_idle;
wire    Package_Sender_U0_ap_ready;
wire    Package_Sender_U0_myIpAddress_read;
wire    Package_Sender_U0_myMacAddress_read;
wire    Package_Sender_U0_arpRequestMetaFifo_read;
wire    Package_Sender_U0_arpReplyMetaFifo_read;
wire   [63:0] Package_Sender_U0_arpDataOut_TDATA;
wire    Package_Sender_U0_arpDataOut_TVALID;
wire   [7:0] Package_Sender_U0_arpDataOut_TKEEP;
wire   [7:0] Package_Sender_U0_arpDataOut_TSTRB;
wire   [0:0] Package_Sender_U0_arpDataOut_TLAST;
wire    arp_table_U0_ap_start;
wire    arp_table_U0_ap_done;
wire    arp_table_U0_ap_continue;
wire    arp_table_U0_ap_idle;
wire    arp_table_U0_ap_ready;
wire    arp_table_U0_arpTableInsertFifo_read;
wire   [31:0] arp_table_U0_arpRequestMetaFifo_din;
wire    arp_table_U0_arpRequestMetaFifo_write;
wire    arp_table_U0_macIpEncode_req_TREADY;
wire   [55:0] arp_table_U0_macIpEncode_rsp_TDATA;
wire    arp_table_U0_macIpEncode_rsp_TVALID;
wire   [39:0] arp_table_U0_macLookup_req_TDATA;
wire    arp_table_U0_macLookup_req_TVALID;
wire    arp_table_U0_macLookup_resp_TREADY;
wire   [87:0] arp_table_U0_macUpdate_req_TDATA;
wire    arp_table_U0_macUpdate_req_TVALID;
wire    arp_table_U0_macUpdate_resp_TREADY;
wire    myMacAddress_c_full_n;
wire   [47:0] myMacAddress_c_dout;
wire   [2:0] myMacAddress_c_num_data_valid;
wire   [2:0] myMacAddress_c_fifo_cap;
wire    myMacAddress_c_empty_n;
wire    myIpAddress_c_full_n;
wire   [31:0] myIpAddress_c_dout;
wire   [2:0] myIpAddress_c_num_data_valid;
wire   [2:0] myIpAddress_c_fifo_cap;
wire    myIpAddress_c_empty_n;
wire    arpReplyMetaFifo_full_n;
wire   [191:0] arpReplyMetaFifo_dout;
wire   [2:0] arpReplyMetaFifo_num_data_valid;
wire   [2:0] arpReplyMetaFifo_fifo_cap;
wire    arpReplyMetaFifo_empty_n;
wire    arpTableInsertFifo_full_n;
wire   [80:0] arpTableInsertFifo_dout;
wire   [2:0] arpTableInsertFifo_num_data_valid;
wire   [2:0] arpTableInsertFifo_fifo_cap;
wire    arpTableInsertFifo_empty_n;
wire    arpRequestMetaFifo_full_n;
wire   [31:0] arpRequestMetaFifo_dout;
wire   [2:0] arpRequestMetaFifo_num_data_valid;
wire   [2:0] arpRequestMetaFifo_fifo_cap;
wire    arpRequestMetaFifo_empty_n;

arp_server_entry_proc entry_proc_U0(
    .ap_clk(ap_clk),
    .ap_rst(ap_rst_n_inv),
    .ap_start(entry_proc_U0_ap_start),
    .ap_done(entry_proc_U0_ap_done),
    .ap_continue(entry_proc_U0_ap_continue),
    .ap_idle(entry_proc_U0_ap_idle),
    .ap_ready(entry_proc_U0_ap_ready),
    .myMacAddress(myMacAddress),
    .myMacAddress_c_din(entry_proc_U0_myMacAddress_c_din),
    .myMacAddress_c_num_data_valid(myMacAddress_c_num_data_valid),
    .myMacAddress_c_fifo_cap(myMacAddress_c_fifo_cap),
    .myMacAddress_c_full_n(myMacAddress_c_full_n),
    .myMacAddress_c_write(entry_proc_U0_myMacAddress_c_write)
);

arp_server_Package_Receiver Package_Receiver_U0(
    .ap_clk(ap_clk),
    .ap_rst(ap_rst_n_inv),
    .ap_start(Package_Receiver_U0_ap_start),
    .ap_done(Package_Receiver_U0_ap_done),
    .ap_continue(Package_Receiver_U0_ap_continue),
    .ap_idle(Package_Receiver_U0_ap_idle),
    .ap_ready(Package_Receiver_U0_ap_ready),
    .myIpAddress_c_din(Package_Receiver_U0_myIpAddress_c_din),
    .myIpAddress_c_num_data_valid(myIpAddress_c_num_data_valid),
    .myIpAddress_c_fifo_cap(myIpAddress_c_fifo_cap),
    .myIpAddress_c_full_n(myIpAddress_c_full_n),
    .myIpAddress_c_write(Package_Receiver_U0_myIpAddress_c_write),
    .arpDataIn_TVALID(arpDataIn_TVALID),
    .arpTableInsertFifo_din(Package_Receiver_U0_arpTableInsertFifo_din),
    .arpTableInsertFifo_num_data_valid(arpTableInsertFifo_num_data_valid),
    .arpTableInsertFifo_fifo_cap(arpTableInsertFifo_fifo_cap),
    .arpTableInsertFifo_full_n(arpTableInsertFifo_full_n),
    .arpTableInsertFifo_write(Package_Receiver_U0_arpTableInsertFifo_write),
    .arpReplyMetaFifo_din(Package_Receiver_U0_arpReplyMetaFifo_din),
    .arpReplyMetaFifo_num_data_valid(arpReplyMetaFifo_num_data_valid),
    .arpReplyMetaFifo_fifo_cap(arpReplyMetaFifo_fifo_cap),
    .arpReplyMetaFifo_full_n(arpReplyMetaFifo_full_n),
    .arpReplyMetaFifo_write(Package_Receiver_U0_arpReplyMetaFifo_write),
    .arpDataIn_TDATA(arpDataIn_TDATA),
    .arpDataIn_TREADY(Package_Receiver_U0_arpDataIn_TREADY),
    .arpDataIn_TKEEP(arpDataIn_TKEEP),
    .arpDataIn_TSTRB(arpDataIn_TSTRB),
    .arpDataIn_TLAST(arpDataIn_TLAST),
    .myIpAddress(myIpAddress)
);

arp_server_Package_Sender Package_Sender_U0(
    .ap_clk(ap_clk),
    .ap_rst(ap_rst_n_inv),
    .ap_start(Package_Sender_U0_ap_start),
    .ap_done(Package_Sender_U0_ap_done),
    .ap_continue(Package_Sender_U0_ap_continue),
    .ap_idle(Package_Sender_U0_ap_idle),
    .ap_ready(Package_Sender_U0_ap_ready),
    .myIpAddress_dout(myIpAddress_c_dout),
    .myIpAddress_num_data_valid(myIpAddress_c_num_data_valid),
    .myIpAddress_fifo_cap(myIpAddress_c_fifo_cap),
    .myIpAddress_empty_n(myIpAddress_c_empty_n),
    .myIpAddress_read(Package_Sender_U0_myIpAddress_read),
    .myMacAddress_dout(myMacAddress_c_dout),
    .myMacAddress_num_data_valid(myMacAddress_c_num_data_valid),
    .myMacAddress_fifo_cap(myMacAddress_c_fifo_cap),
    .myMacAddress_empty_n(myMacAddress_c_empty_n),
    .myMacAddress_read(Package_Sender_U0_myMacAddress_read),
    .arpRequestMetaFifo_dout(arpRequestMetaFifo_dout),
    .arpRequestMetaFifo_num_data_valid(arpRequestMetaFifo_num_data_valid),
    .arpRequestMetaFifo_fifo_cap(arpRequestMetaFifo_fifo_cap),
    .arpRequestMetaFifo_empty_n(arpRequestMetaFifo_empty_n),
    .arpRequestMetaFifo_read(Package_Sender_U0_arpRequestMetaFifo_read),
    .arpReplyMetaFifo_dout(arpReplyMetaFifo_dout),
    .arpReplyMetaFifo_num_data_valid(arpReplyMetaFifo_num_data_valid),
    .arpReplyMetaFifo_fifo_cap(arpReplyMetaFifo_fifo_cap),
    .arpReplyMetaFifo_empty_n(arpReplyMetaFifo_empty_n),
    .arpReplyMetaFifo_read(Package_Sender_U0_arpReplyMetaFifo_read),
    .arpDataOut_TREADY(arpDataOut_TREADY),
    .arpDataOut_TDATA(Package_Sender_U0_arpDataOut_TDATA),
    .arpDataOut_TVALID(Package_Sender_U0_arpDataOut_TVALID),
    .arpDataOut_TKEEP(Package_Sender_U0_arpDataOut_TKEEP),
    .arpDataOut_TSTRB(Package_Sender_U0_arpDataOut_TSTRB),
    .arpDataOut_TLAST(Package_Sender_U0_arpDataOut_TLAST)
);

arp_server_arp_table arp_table_U0(
    .ap_clk(ap_clk),
    .ap_rst(ap_rst_n_inv),
    .ap_start(arp_table_U0_ap_start),
    .ap_done(arp_table_U0_ap_done),
    .ap_continue(arp_table_U0_ap_continue),
    .ap_idle(arp_table_U0_ap_idle),
    .ap_ready(arp_table_U0_ap_ready),
    .macUpdate_resp_TVALID(macUpdate_resp_TVALID),
    .macLookup_resp_TVALID(macLookup_resp_TVALID),
    .arpTableInsertFifo_dout(arpTableInsertFifo_dout),
    .arpTableInsertFifo_num_data_valid(arpTableInsertFifo_num_data_valid),
    .arpTableInsertFifo_fifo_cap(arpTableInsertFifo_fifo_cap),
    .arpTableInsertFifo_empty_n(arpTableInsertFifo_empty_n),
    .arpTableInsertFifo_read(arp_table_U0_arpTableInsertFifo_read),
    .macIpEncode_req_TVALID(macIpEncode_req_TVALID),
    .macIpEncode_rsp_TREADY(macIpEncode_rsp_TREADY),
    .arpRequestMetaFifo_din(arp_table_U0_arpRequestMetaFifo_din),
    .arpRequestMetaFifo_num_data_valid(arpRequestMetaFifo_num_data_valid),
    .arpRequestMetaFifo_fifo_cap(arpRequestMetaFifo_fifo_cap),
    .arpRequestMetaFifo_full_n(arpRequestMetaFifo_full_n),
    .arpRequestMetaFifo_write(arp_table_U0_arpRequestMetaFifo_write),
    .macUpdate_req_TREADY(macUpdate_req_TREADY),
    .macLookup_req_TREADY(macLookup_req_TREADY),
    .macIpEncode_req_TDATA(macIpEncode_req_TDATA),
    .macIpEncode_req_TREADY(arp_table_U0_macIpEncode_req_TREADY),
    .macIpEncode_rsp_TDATA(arp_table_U0_macIpEncode_rsp_TDATA),
    .macIpEncode_rsp_TVALID(arp_table_U0_macIpEncode_rsp_TVALID),
    .macLookup_req_TDATA(arp_table_U0_macLookup_req_TDATA),
    .macLookup_req_TVALID(arp_table_U0_macLookup_req_TVALID),
    .macLookup_resp_TDATA(macLookup_resp_TDATA),
    .macLookup_resp_TREADY(arp_table_U0_macLookup_resp_TREADY),
    .macUpdate_req_TDATA(arp_table_U0_macUpdate_req_TDATA),
    .macUpdate_req_TVALID(arp_table_U0_macUpdate_req_TVALID),
    .macUpdate_resp_TDATA(macUpdate_resp_TDATA),
    .macUpdate_resp_TREADY(arp_table_U0_macUpdate_resp_TREADY)
);

arp_server_fifo_w48_d3_S myMacAddress_c_U(
    .clk(ap_clk),
    .reset(ap_rst_n_inv),
    .if_read_ce(1'b1),
    .if_write_ce(1'b1),
    .if_din(entry_proc_U0_myMacAddress_c_din),
    .if_full_n(myMacAddress_c_full_n),
    .if_write(entry_proc_U0_myMacAddress_c_write),
    .if_dout(myMacAddress_c_dout),
    .if_num_data_valid(myMacAddress_c_num_data_valid),
    .if_fifo_cap(myMacAddress_c_fifo_cap),
    .if_empty_n(myMacAddress_c_empty_n),
    .if_read(Package_Sender_U0_myMacAddress_read)
);

arp_server_fifo_w32_d2_S myIpAddress_c_U(
    .clk(ap_clk),
    .reset(ap_rst_n_inv),
    .if_read_ce(1'b1),
    .if_write_ce(1'b1),
    .if_din(Package_Receiver_U0_myIpAddress_c_din),
    .if_full_n(myIpAddress_c_full_n),
    .if_write(Package_Receiver_U0_myIpAddress_c_write),
    .if_dout(myIpAddress_c_dout),
    .if_num_data_valid(myIpAddress_c_num_data_valid),
    .if_fifo_cap(myIpAddress_c_fifo_cap),
    .if_empty_n(myIpAddress_c_empty_n),
    .if_read(Package_Sender_U0_myIpAddress_read)
);

arp_server_fifo_w192_d4_S arpReplyMetaFifo_U(
    .clk(ap_clk),
    .reset(ap_rst_n_inv),
    .if_read_ce(1'b1),
    .if_write_ce(1'b1),
    .if_din(Package_Receiver_U0_arpReplyMetaFifo_din),
    .if_full_n(arpReplyMetaFifo_full_n),
    .if_write(Package_Receiver_U0_arpReplyMetaFifo_write),
    .if_dout(arpReplyMetaFifo_dout),
    .if_num_data_valid(arpReplyMetaFifo_num_data_valid),
    .if_fifo_cap(arpReplyMetaFifo_fifo_cap),
    .if_empty_n(arpReplyMetaFifo_empty_n),
    .if_read(Package_Sender_U0_arpReplyMetaFifo_read)
);

arp_server_fifo_w81_d4_S arpTableInsertFifo_U(
    .clk(ap_clk),
    .reset(ap_rst_n_inv),
    .if_read_ce(1'b1),
    .if_write_ce(1'b1),
    .if_din(Package_Receiver_U0_arpTableInsertFifo_din),
    .if_full_n(arpTableInsertFifo_full_n),
    .if_write(Package_Receiver_U0_arpTableInsertFifo_write),
    .if_dout(arpTableInsertFifo_dout),
    .if_num_data_valid(arpTableInsertFifo_num_data_valid),
    .if_fifo_cap(arpTableInsertFifo_fifo_cap),
    .if_empty_n(arpTableInsertFifo_empty_n),
    .if_read(arp_table_U0_arpTableInsertFifo_read)
);

arp_server_fifo_w32_d4_S arpRequestMetaFifo_U(
    .clk(ap_clk),
    .reset(ap_rst_n_inv),
    .if_read_ce(1'b1),
    .if_write_ce(1'b1),
    .if_din(arp_table_U0_arpRequestMetaFifo_din),
    .if_full_n(arpRequestMetaFifo_full_n),
    .if_write(arp_table_U0_arpRequestMetaFifo_write),
    .if_dout(arpRequestMetaFifo_dout),
    .if_num_data_valid(arpRequestMetaFifo_num_data_valid),
    .if_fifo_cap(arpRequestMetaFifo_fifo_cap),
    .if_empty_n(arpRequestMetaFifo_empty_n),
    .if_read(Package_Sender_U0_arpRequestMetaFifo_read)
);

assign Package_Receiver_U0_ap_continue = 1'b1;

assign Package_Receiver_U0_ap_start = 1'b1;

assign Package_Sender_U0_ap_continue = 1'b1;

assign Package_Sender_U0_ap_start = 1'b1;

always @ (*) begin
    ap_rst_n_inv = ~ap_rst_n;
end

assign arpDataIn_TREADY = Package_Receiver_U0_arpDataIn_TREADY;

assign arpDataOut_TDATA = Package_Sender_U0_arpDataOut_TDATA;

assign arpDataOut_TKEEP = Package_Sender_U0_arpDataOut_TKEEP;

assign arpDataOut_TLAST = Package_Sender_U0_arpDataOut_TLAST;

assign arpDataOut_TSTRB = Package_Sender_U0_arpDataOut_TSTRB;

assign arpDataOut_TVALID = Package_Sender_U0_arpDataOut_TVALID;

assign arp_table_U0_ap_continue = 1'b1;

assign arp_table_U0_ap_start = 1'b1;

assign entry_proc_U0_ap_continue = 1'b1;

assign entry_proc_U0_ap_start = 1'b1;

assign macIpEncode_req_TREADY = arp_table_U0_macIpEncode_req_TREADY;

assign macIpEncode_rsp_TDATA = arp_table_U0_macIpEncode_rsp_TDATA;

assign macIpEncode_rsp_TVALID = arp_table_U0_macIpEncode_rsp_TVALID;

assign macLookup_req_TDATA = arp_table_U0_macLookup_req_TDATA;

assign macLookup_req_TVALID = arp_table_U0_macLookup_req_TVALID;

assign macLookup_resp_TREADY = arp_table_U0_macLookup_resp_TREADY;

assign macUpdate_req_TDATA = arp_table_U0_macUpdate_req_TDATA;

assign macUpdate_req_TVALID = arp_table_U0_macUpdate_req_TVALID;

assign macUpdate_resp_TREADY = arp_table_U0_macUpdate_resp_TREADY;


reg find_df_deadlock = 0;
// synthesis translate_off
`include "arp_server_hls_deadlock_detector.vh"
// synthesis translate_on

endmodule //arp_server
