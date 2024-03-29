-- ==============================================================
-- Generated by Vitis HLS v2023.2.1
-- Copyright 1986-2022 Xilinx, Inc. All Rights Reserved.
-- Copyright 2022-2023 Advanced Micro Devices, Inc. All Rights Reserved.
-- ==============================================================

library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.numeric_std.all;

entity arp_server is
port (
    arpDataIn_TDATA : IN STD_LOGIC_VECTOR (63 downto 0);
    arpDataIn_TKEEP : IN STD_LOGIC_VECTOR (7 downto 0);
    arpDataIn_TSTRB : IN STD_LOGIC_VECTOR (7 downto 0);
    arpDataIn_TLAST : IN STD_LOGIC_VECTOR (0 downto 0);
    macIpEncode_req_TDATA : IN STD_LOGIC_VECTOR (31 downto 0);
    arpDataOut_TDATA : OUT STD_LOGIC_VECTOR (63 downto 0);
    arpDataOut_TKEEP : OUT STD_LOGIC_VECTOR (7 downto 0);
    arpDataOut_TSTRB : OUT STD_LOGIC_VECTOR (7 downto 0);
    arpDataOut_TLAST : OUT STD_LOGIC_VECTOR (0 downto 0);
    macIpEncode_rsp_TDATA : OUT STD_LOGIC_VECTOR (55 downto 0);
    macLookup_req_TDATA : OUT STD_LOGIC_VECTOR (39 downto 0);
    macLookup_resp_TDATA : IN STD_LOGIC_VECTOR (55 downto 0);
    macUpdate_req_TDATA : OUT STD_LOGIC_VECTOR (87 downto 0);
    macUpdate_resp_TDATA : IN STD_LOGIC_VECTOR (55 downto 0);
    myMacAddress : IN STD_LOGIC_VECTOR (47 downto 0);
    myIpAddress : IN STD_LOGIC_VECTOR (31 downto 0);
    ap_clk : IN STD_LOGIC;
    ap_rst_n : IN STD_LOGIC;
    arpDataIn_TVALID : IN STD_LOGIC;
    arpDataIn_TREADY : OUT STD_LOGIC;
    arpDataOut_TVALID : OUT STD_LOGIC;
    arpDataOut_TREADY : IN STD_LOGIC;
    macIpEncode_req_TVALID : IN STD_LOGIC;
    macIpEncode_req_TREADY : OUT STD_LOGIC;
    macIpEncode_rsp_TVALID : OUT STD_LOGIC;
    macIpEncode_rsp_TREADY : IN STD_LOGIC;
    macLookup_req_TVALID : OUT STD_LOGIC;
    macLookup_req_TREADY : IN STD_LOGIC;
    macLookup_resp_TVALID : IN STD_LOGIC;
    macLookup_resp_TREADY : OUT STD_LOGIC;
    macUpdate_req_TVALID : OUT STD_LOGIC;
    macUpdate_req_TREADY : IN STD_LOGIC;
    macUpdate_resp_TVALID : IN STD_LOGIC;
    macUpdate_resp_TREADY : OUT STD_LOGIC );
end;


architecture behav of arp_server is 
    attribute CORE_GENERATION_INFO : STRING;
    attribute CORE_GENERATION_INFO of behav : architecture is
    "arp_server_arp_server,hls_ip_2023_2_1,{HLS_INPUT_TYPE=cxx,HLS_INPUT_FLOAT=0,HLS_INPUT_FIXED=0,HLS_INPUT_PART=xcku5p-ffvb676-2-e,HLS_INPUT_CLOCK=10.000000,HLS_INPUT_ARCH=dataflow,HLS_SYN_CLOCK=2.855125,HLS_SYN_LAT=5,HLS_SYN_TPT=1,HLS_SYN_MEM=0,HLS_SYN_DSP=0,HLS_SYN_FF=1777,HLS_SYN_LUT=1140,HLS_VERSION=2023_2_1}";
    constant ap_const_logic_1 : STD_LOGIC := '1';
    constant ap_const_logic_0 : STD_LOGIC := '0';

    signal ap_rst_n_inv : STD_LOGIC;
    signal entry_proc_U0_ap_start : STD_LOGIC;
    signal entry_proc_U0_ap_done : STD_LOGIC;
    signal entry_proc_U0_ap_continue : STD_LOGIC;
    signal entry_proc_U0_ap_idle : STD_LOGIC;
    signal entry_proc_U0_ap_ready : STD_LOGIC;
    signal entry_proc_U0_myMacAddress_c_din : STD_LOGIC_VECTOR (47 downto 0);
    signal entry_proc_U0_myMacAddress_c_write : STD_LOGIC;
    signal Package_Receiver_U0_ap_start : STD_LOGIC;
    signal Package_Receiver_U0_ap_done : STD_LOGIC;
    signal Package_Receiver_U0_ap_continue : STD_LOGIC;
    signal Package_Receiver_U0_ap_idle : STD_LOGIC;
    signal Package_Receiver_U0_ap_ready : STD_LOGIC;
    signal Package_Receiver_U0_myIpAddress_c_din : STD_LOGIC_VECTOR (31 downto 0);
    signal Package_Receiver_U0_myIpAddress_c_write : STD_LOGIC;
    signal Package_Receiver_U0_arpTableInsertFifo_din : STD_LOGIC_VECTOR (80 downto 0);
    signal Package_Receiver_U0_arpTableInsertFifo_write : STD_LOGIC;
    signal Package_Receiver_U0_arpReplyMetaFifo_din : STD_LOGIC_VECTOR (191 downto 0);
    signal Package_Receiver_U0_arpReplyMetaFifo_write : STD_LOGIC;
    signal Package_Receiver_U0_arpDataIn_TREADY : STD_LOGIC;
    signal Package_Sender_U0_ap_start : STD_LOGIC;
    signal Package_Sender_U0_ap_done : STD_LOGIC;
    signal Package_Sender_U0_ap_continue : STD_LOGIC;
    signal Package_Sender_U0_ap_idle : STD_LOGIC;
    signal Package_Sender_U0_ap_ready : STD_LOGIC;
    signal Package_Sender_U0_myIpAddress_read : STD_LOGIC;
    signal Package_Sender_U0_myMacAddress_read : STD_LOGIC;
    signal Package_Sender_U0_arpRequestMetaFifo_read : STD_LOGIC;
    signal Package_Sender_U0_arpReplyMetaFifo_read : STD_LOGIC;
    signal Package_Sender_U0_arpDataOut_TDATA : STD_LOGIC_VECTOR (63 downto 0);
    signal Package_Sender_U0_arpDataOut_TVALID : STD_LOGIC;
    signal Package_Sender_U0_arpDataOut_TKEEP : STD_LOGIC_VECTOR (7 downto 0);
    signal Package_Sender_U0_arpDataOut_TSTRB : STD_LOGIC_VECTOR (7 downto 0);
    signal Package_Sender_U0_arpDataOut_TLAST : STD_LOGIC_VECTOR (0 downto 0);
    signal arp_table_U0_ap_start : STD_LOGIC;
    signal arp_table_U0_ap_done : STD_LOGIC;
    signal arp_table_U0_ap_continue : STD_LOGIC;
    signal arp_table_U0_ap_idle : STD_LOGIC;
    signal arp_table_U0_ap_ready : STD_LOGIC;
    signal arp_table_U0_arpTableInsertFifo_read : STD_LOGIC;
    signal arp_table_U0_arpRequestMetaFifo_din : STD_LOGIC_VECTOR (31 downto 0);
    signal arp_table_U0_arpRequestMetaFifo_write : STD_LOGIC;
    signal arp_table_U0_macIpEncode_req_TREADY : STD_LOGIC;
    signal arp_table_U0_macIpEncode_rsp_TDATA : STD_LOGIC_VECTOR (55 downto 0);
    signal arp_table_U0_macIpEncode_rsp_TVALID : STD_LOGIC;
    signal arp_table_U0_macLookup_req_TDATA : STD_LOGIC_VECTOR (39 downto 0);
    signal arp_table_U0_macLookup_req_TVALID : STD_LOGIC;
    signal arp_table_U0_macLookup_resp_TREADY : STD_LOGIC;
    signal arp_table_U0_macUpdate_req_TDATA : STD_LOGIC_VECTOR (87 downto 0);
    signal arp_table_U0_macUpdate_req_TVALID : STD_LOGIC;
    signal arp_table_U0_macUpdate_resp_TREADY : STD_LOGIC;
    signal myMacAddress_c_full_n : STD_LOGIC;
    signal myMacAddress_c_dout : STD_LOGIC_VECTOR (47 downto 0);
    signal myMacAddress_c_num_data_valid : STD_LOGIC_VECTOR (2 downto 0);
    signal myMacAddress_c_fifo_cap : STD_LOGIC_VECTOR (2 downto 0);
    signal myMacAddress_c_empty_n : STD_LOGIC;
    signal myIpAddress_c_full_n : STD_LOGIC;
    signal myIpAddress_c_dout : STD_LOGIC_VECTOR (31 downto 0);
    signal myIpAddress_c_num_data_valid : STD_LOGIC_VECTOR (2 downto 0);
    signal myIpAddress_c_fifo_cap : STD_LOGIC_VECTOR (2 downto 0);
    signal myIpAddress_c_empty_n : STD_LOGIC;
    signal arpReplyMetaFifo_full_n : STD_LOGIC;
    signal arpReplyMetaFifo_dout : STD_LOGIC_VECTOR (191 downto 0);
    signal arpReplyMetaFifo_num_data_valid : STD_LOGIC_VECTOR (2 downto 0);
    signal arpReplyMetaFifo_fifo_cap : STD_LOGIC_VECTOR (2 downto 0);
    signal arpReplyMetaFifo_empty_n : STD_LOGIC;
    signal arpTableInsertFifo_full_n : STD_LOGIC;
    signal arpTableInsertFifo_dout : STD_LOGIC_VECTOR (80 downto 0);
    signal arpTableInsertFifo_num_data_valid : STD_LOGIC_VECTOR (2 downto 0);
    signal arpTableInsertFifo_fifo_cap : STD_LOGIC_VECTOR (2 downto 0);
    signal arpTableInsertFifo_empty_n : STD_LOGIC;
    signal arpRequestMetaFifo_full_n : STD_LOGIC;
    signal arpRequestMetaFifo_dout : STD_LOGIC_VECTOR (31 downto 0);
    signal arpRequestMetaFifo_num_data_valid : STD_LOGIC_VECTOR (2 downto 0);
    signal arpRequestMetaFifo_fifo_cap : STD_LOGIC_VECTOR (2 downto 0);
    signal arpRequestMetaFifo_empty_n : STD_LOGIC;

    component arp_server_entry_proc IS
    port (
        ap_clk : IN STD_LOGIC;
        ap_rst : IN STD_LOGIC;
        ap_start : IN STD_LOGIC;
        ap_done : OUT STD_LOGIC;
        ap_continue : IN STD_LOGIC;
        ap_idle : OUT STD_LOGIC;
        ap_ready : OUT STD_LOGIC;
        myMacAddress : IN STD_LOGIC_VECTOR (47 downto 0);
        myMacAddress_c_din : OUT STD_LOGIC_VECTOR (47 downto 0);
        myMacAddress_c_num_data_valid : IN STD_LOGIC_VECTOR (2 downto 0);
        myMacAddress_c_fifo_cap : IN STD_LOGIC_VECTOR (2 downto 0);
        myMacAddress_c_full_n : IN STD_LOGIC;
        myMacAddress_c_write : OUT STD_LOGIC );
    end component;


    component arp_server_Package_Receiver IS
    port (
        ap_clk : IN STD_LOGIC;
        ap_rst : IN STD_LOGIC;
        ap_start : IN STD_LOGIC;
        ap_done : OUT STD_LOGIC;
        ap_continue : IN STD_LOGIC;
        ap_idle : OUT STD_LOGIC;
        ap_ready : OUT STD_LOGIC;
        myIpAddress_c_din : OUT STD_LOGIC_VECTOR (31 downto 0);
        myIpAddress_c_num_data_valid : IN STD_LOGIC_VECTOR (2 downto 0);
        myIpAddress_c_fifo_cap : IN STD_LOGIC_VECTOR (2 downto 0);
        myIpAddress_c_full_n : IN STD_LOGIC;
        myIpAddress_c_write : OUT STD_LOGIC;
        arpDataIn_TVALID : IN STD_LOGIC;
        arpTableInsertFifo_din : OUT STD_LOGIC_VECTOR (80 downto 0);
        arpTableInsertFifo_num_data_valid : IN STD_LOGIC_VECTOR (2 downto 0);
        arpTableInsertFifo_fifo_cap : IN STD_LOGIC_VECTOR (2 downto 0);
        arpTableInsertFifo_full_n : IN STD_LOGIC;
        arpTableInsertFifo_write : OUT STD_LOGIC;
        arpReplyMetaFifo_din : OUT STD_LOGIC_VECTOR (191 downto 0);
        arpReplyMetaFifo_num_data_valid : IN STD_LOGIC_VECTOR (2 downto 0);
        arpReplyMetaFifo_fifo_cap : IN STD_LOGIC_VECTOR (2 downto 0);
        arpReplyMetaFifo_full_n : IN STD_LOGIC;
        arpReplyMetaFifo_write : OUT STD_LOGIC;
        arpDataIn_TDATA : IN STD_LOGIC_VECTOR (63 downto 0);
        arpDataIn_TREADY : OUT STD_LOGIC;
        arpDataIn_TKEEP : IN STD_LOGIC_VECTOR (7 downto 0);
        arpDataIn_TSTRB : IN STD_LOGIC_VECTOR (7 downto 0);
        arpDataIn_TLAST : IN STD_LOGIC_VECTOR (0 downto 0);
        myIpAddress : IN STD_LOGIC_VECTOR (31 downto 0) );
    end component;


    component arp_server_Package_Sender IS
    port (
        ap_clk : IN STD_LOGIC;
        ap_rst : IN STD_LOGIC;
        ap_start : IN STD_LOGIC;
        ap_done : OUT STD_LOGIC;
        ap_continue : IN STD_LOGIC;
        ap_idle : OUT STD_LOGIC;
        ap_ready : OUT STD_LOGIC;
        myIpAddress_dout : IN STD_LOGIC_VECTOR (31 downto 0);
        myIpAddress_num_data_valid : IN STD_LOGIC_VECTOR (2 downto 0);
        myIpAddress_fifo_cap : IN STD_LOGIC_VECTOR (2 downto 0);
        myIpAddress_empty_n : IN STD_LOGIC;
        myIpAddress_read : OUT STD_LOGIC;
        myMacAddress_dout : IN STD_LOGIC_VECTOR (47 downto 0);
        myMacAddress_num_data_valid : IN STD_LOGIC_VECTOR (2 downto 0);
        myMacAddress_fifo_cap : IN STD_LOGIC_VECTOR (2 downto 0);
        myMacAddress_empty_n : IN STD_LOGIC;
        myMacAddress_read : OUT STD_LOGIC;
        arpRequestMetaFifo_dout : IN STD_LOGIC_VECTOR (31 downto 0);
        arpRequestMetaFifo_num_data_valid : IN STD_LOGIC_VECTOR (2 downto 0);
        arpRequestMetaFifo_fifo_cap : IN STD_LOGIC_VECTOR (2 downto 0);
        arpRequestMetaFifo_empty_n : IN STD_LOGIC;
        arpRequestMetaFifo_read : OUT STD_LOGIC;
        arpReplyMetaFifo_dout : IN STD_LOGIC_VECTOR (191 downto 0);
        arpReplyMetaFifo_num_data_valid : IN STD_LOGIC_VECTOR (2 downto 0);
        arpReplyMetaFifo_fifo_cap : IN STD_LOGIC_VECTOR (2 downto 0);
        arpReplyMetaFifo_empty_n : IN STD_LOGIC;
        arpReplyMetaFifo_read : OUT STD_LOGIC;
        arpDataOut_TREADY : IN STD_LOGIC;
        arpDataOut_TDATA : OUT STD_LOGIC_VECTOR (63 downto 0);
        arpDataOut_TVALID : OUT STD_LOGIC;
        arpDataOut_TKEEP : OUT STD_LOGIC_VECTOR (7 downto 0);
        arpDataOut_TSTRB : OUT STD_LOGIC_VECTOR (7 downto 0);
        arpDataOut_TLAST : OUT STD_LOGIC_VECTOR (0 downto 0) );
    end component;


    component arp_server_arp_table IS
    port (
        ap_clk : IN STD_LOGIC;
        ap_rst : IN STD_LOGIC;
        ap_start : IN STD_LOGIC;
        ap_done : OUT STD_LOGIC;
        ap_continue : IN STD_LOGIC;
        ap_idle : OUT STD_LOGIC;
        ap_ready : OUT STD_LOGIC;
        macUpdate_resp_TVALID : IN STD_LOGIC;
        macLookup_resp_TVALID : IN STD_LOGIC;
        arpTableInsertFifo_dout : IN STD_LOGIC_VECTOR (80 downto 0);
        arpTableInsertFifo_num_data_valid : IN STD_LOGIC_VECTOR (2 downto 0);
        arpTableInsertFifo_fifo_cap : IN STD_LOGIC_VECTOR (2 downto 0);
        arpTableInsertFifo_empty_n : IN STD_LOGIC;
        arpTableInsertFifo_read : OUT STD_LOGIC;
        macIpEncode_req_TVALID : IN STD_LOGIC;
        macIpEncode_rsp_TREADY : IN STD_LOGIC;
        arpRequestMetaFifo_din : OUT STD_LOGIC_VECTOR (31 downto 0);
        arpRequestMetaFifo_num_data_valid : IN STD_LOGIC_VECTOR (2 downto 0);
        arpRequestMetaFifo_fifo_cap : IN STD_LOGIC_VECTOR (2 downto 0);
        arpRequestMetaFifo_full_n : IN STD_LOGIC;
        arpRequestMetaFifo_write : OUT STD_LOGIC;
        macUpdate_req_TREADY : IN STD_LOGIC;
        macLookup_req_TREADY : IN STD_LOGIC;
        macIpEncode_req_TDATA : IN STD_LOGIC_VECTOR (31 downto 0);
        macIpEncode_req_TREADY : OUT STD_LOGIC;
        macIpEncode_rsp_TDATA : OUT STD_LOGIC_VECTOR (55 downto 0);
        macIpEncode_rsp_TVALID : OUT STD_LOGIC;
        macLookup_req_TDATA : OUT STD_LOGIC_VECTOR (39 downto 0);
        macLookup_req_TVALID : OUT STD_LOGIC;
        macLookup_resp_TDATA : IN STD_LOGIC_VECTOR (55 downto 0);
        macLookup_resp_TREADY : OUT STD_LOGIC;
        macUpdate_req_TDATA : OUT STD_LOGIC_VECTOR (87 downto 0);
        macUpdate_req_TVALID : OUT STD_LOGIC;
        macUpdate_resp_TDATA : IN STD_LOGIC_VECTOR (55 downto 0);
        macUpdate_resp_TREADY : OUT STD_LOGIC );
    end component;


    component arp_server_fifo_w48_d3_S IS
    port (
        clk : IN STD_LOGIC;
        reset : IN STD_LOGIC;
        if_read_ce : IN STD_LOGIC;
        if_write_ce : IN STD_LOGIC;
        if_din : IN STD_LOGIC_VECTOR (47 downto 0);
        if_full_n : OUT STD_LOGIC;
        if_write : IN STD_LOGIC;
        if_dout : OUT STD_LOGIC_VECTOR (47 downto 0);
        if_num_data_valid : OUT STD_LOGIC_VECTOR (2 downto 0);
        if_fifo_cap : OUT STD_LOGIC_VECTOR (2 downto 0);
        if_empty_n : OUT STD_LOGIC;
        if_read : IN STD_LOGIC );
    end component;


    component arp_server_fifo_w32_d2_S IS
    port (
        clk : IN STD_LOGIC;
        reset : IN STD_LOGIC;
        if_read_ce : IN STD_LOGIC;
        if_write_ce : IN STD_LOGIC;
        if_din : IN STD_LOGIC_VECTOR (31 downto 0);
        if_full_n : OUT STD_LOGIC;
        if_write : IN STD_LOGIC;
        if_dout : OUT STD_LOGIC_VECTOR (31 downto 0);
        if_num_data_valid : OUT STD_LOGIC_VECTOR (2 downto 0);
        if_fifo_cap : OUT STD_LOGIC_VECTOR (2 downto 0);
        if_empty_n : OUT STD_LOGIC;
        if_read : IN STD_LOGIC );
    end component;


    component arp_server_fifo_w192_d4_S IS
    port (
        clk : IN STD_LOGIC;
        reset : IN STD_LOGIC;
        if_read_ce : IN STD_LOGIC;
        if_write_ce : IN STD_LOGIC;
        if_din : IN STD_LOGIC_VECTOR (191 downto 0);
        if_full_n : OUT STD_LOGIC;
        if_write : IN STD_LOGIC;
        if_dout : OUT STD_LOGIC_VECTOR (191 downto 0);
        if_num_data_valid : OUT STD_LOGIC_VECTOR (2 downto 0);
        if_fifo_cap : OUT STD_LOGIC_VECTOR (2 downto 0);
        if_empty_n : OUT STD_LOGIC;
        if_read : IN STD_LOGIC );
    end component;


    component arp_server_fifo_w81_d4_S IS
    port (
        clk : IN STD_LOGIC;
        reset : IN STD_LOGIC;
        if_read_ce : IN STD_LOGIC;
        if_write_ce : IN STD_LOGIC;
        if_din : IN STD_LOGIC_VECTOR (80 downto 0);
        if_full_n : OUT STD_LOGIC;
        if_write : IN STD_LOGIC;
        if_dout : OUT STD_LOGIC_VECTOR (80 downto 0);
        if_num_data_valid : OUT STD_LOGIC_VECTOR (2 downto 0);
        if_fifo_cap : OUT STD_LOGIC_VECTOR (2 downto 0);
        if_empty_n : OUT STD_LOGIC;
        if_read : IN STD_LOGIC );
    end component;


    component arp_server_fifo_w32_d4_S IS
    port (
        clk : IN STD_LOGIC;
        reset : IN STD_LOGIC;
        if_read_ce : IN STD_LOGIC;
        if_write_ce : IN STD_LOGIC;
        if_din : IN STD_LOGIC_VECTOR (31 downto 0);
        if_full_n : OUT STD_LOGIC;
        if_write : IN STD_LOGIC;
        if_dout : OUT STD_LOGIC_VECTOR (31 downto 0);
        if_num_data_valid : OUT STD_LOGIC_VECTOR (2 downto 0);
        if_fifo_cap : OUT STD_LOGIC_VECTOR (2 downto 0);
        if_empty_n : OUT STD_LOGIC;
        if_read : IN STD_LOGIC );
    end component;



begin
    entry_proc_U0 : component arp_server_entry_proc
    port map (
        ap_clk => ap_clk,
        ap_rst => ap_rst_n_inv,
        ap_start => entry_proc_U0_ap_start,
        ap_done => entry_proc_U0_ap_done,
        ap_continue => entry_proc_U0_ap_continue,
        ap_idle => entry_proc_U0_ap_idle,
        ap_ready => entry_proc_U0_ap_ready,
        myMacAddress => myMacAddress,
        myMacAddress_c_din => entry_proc_U0_myMacAddress_c_din,
        myMacAddress_c_num_data_valid => myMacAddress_c_num_data_valid,
        myMacAddress_c_fifo_cap => myMacAddress_c_fifo_cap,
        myMacAddress_c_full_n => myMacAddress_c_full_n,
        myMacAddress_c_write => entry_proc_U0_myMacAddress_c_write);

    Package_Receiver_U0 : component arp_server_Package_Receiver
    port map (
        ap_clk => ap_clk,
        ap_rst => ap_rst_n_inv,
        ap_start => Package_Receiver_U0_ap_start,
        ap_done => Package_Receiver_U0_ap_done,
        ap_continue => Package_Receiver_U0_ap_continue,
        ap_idle => Package_Receiver_U0_ap_idle,
        ap_ready => Package_Receiver_U0_ap_ready,
        myIpAddress_c_din => Package_Receiver_U0_myIpAddress_c_din,
        myIpAddress_c_num_data_valid => myIpAddress_c_num_data_valid,
        myIpAddress_c_fifo_cap => myIpAddress_c_fifo_cap,
        myIpAddress_c_full_n => myIpAddress_c_full_n,
        myIpAddress_c_write => Package_Receiver_U0_myIpAddress_c_write,
        arpDataIn_TVALID => arpDataIn_TVALID,
        arpTableInsertFifo_din => Package_Receiver_U0_arpTableInsertFifo_din,
        arpTableInsertFifo_num_data_valid => arpTableInsertFifo_num_data_valid,
        arpTableInsertFifo_fifo_cap => arpTableInsertFifo_fifo_cap,
        arpTableInsertFifo_full_n => arpTableInsertFifo_full_n,
        arpTableInsertFifo_write => Package_Receiver_U0_arpTableInsertFifo_write,
        arpReplyMetaFifo_din => Package_Receiver_U0_arpReplyMetaFifo_din,
        arpReplyMetaFifo_num_data_valid => arpReplyMetaFifo_num_data_valid,
        arpReplyMetaFifo_fifo_cap => arpReplyMetaFifo_fifo_cap,
        arpReplyMetaFifo_full_n => arpReplyMetaFifo_full_n,
        arpReplyMetaFifo_write => Package_Receiver_U0_arpReplyMetaFifo_write,
        arpDataIn_TDATA => arpDataIn_TDATA,
        arpDataIn_TREADY => Package_Receiver_U0_arpDataIn_TREADY,
        arpDataIn_TKEEP => arpDataIn_TKEEP,
        arpDataIn_TSTRB => arpDataIn_TSTRB,
        arpDataIn_TLAST => arpDataIn_TLAST,
        myIpAddress => myIpAddress);

    Package_Sender_U0 : component arp_server_Package_Sender
    port map (
        ap_clk => ap_clk,
        ap_rst => ap_rst_n_inv,
        ap_start => Package_Sender_U0_ap_start,
        ap_done => Package_Sender_U0_ap_done,
        ap_continue => Package_Sender_U0_ap_continue,
        ap_idle => Package_Sender_U0_ap_idle,
        ap_ready => Package_Sender_U0_ap_ready,
        myIpAddress_dout => myIpAddress_c_dout,
        myIpAddress_num_data_valid => myIpAddress_c_num_data_valid,
        myIpAddress_fifo_cap => myIpAddress_c_fifo_cap,
        myIpAddress_empty_n => myIpAddress_c_empty_n,
        myIpAddress_read => Package_Sender_U0_myIpAddress_read,
        myMacAddress_dout => myMacAddress_c_dout,
        myMacAddress_num_data_valid => myMacAddress_c_num_data_valid,
        myMacAddress_fifo_cap => myMacAddress_c_fifo_cap,
        myMacAddress_empty_n => myMacAddress_c_empty_n,
        myMacAddress_read => Package_Sender_U0_myMacAddress_read,
        arpRequestMetaFifo_dout => arpRequestMetaFifo_dout,
        arpRequestMetaFifo_num_data_valid => arpRequestMetaFifo_num_data_valid,
        arpRequestMetaFifo_fifo_cap => arpRequestMetaFifo_fifo_cap,
        arpRequestMetaFifo_empty_n => arpRequestMetaFifo_empty_n,
        arpRequestMetaFifo_read => Package_Sender_U0_arpRequestMetaFifo_read,
        arpReplyMetaFifo_dout => arpReplyMetaFifo_dout,
        arpReplyMetaFifo_num_data_valid => arpReplyMetaFifo_num_data_valid,
        arpReplyMetaFifo_fifo_cap => arpReplyMetaFifo_fifo_cap,
        arpReplyMetaFifo_empty_n => arpReplyMetaFifo_empty_n,
        arpReplyMetaFifo_read => Package_Sender_U0_arpReplyMetaFifo_read,
        arpDataOut_TREADY => arpDataOut_TREADY,
        arpDataOut_TDATA => Package_Sender_U0_arpDataOut_TDATA,
        arpDataOut_TVALID => Package_Sender_U0_arpDataOut_TVALID,
        arpDataOut_TKEEP => Package_Sender_U0_arpDataOut_TKEEP,
        arpDataOut_TSTRB => Package_Sender_U0_arpDataOut_TSTRB,
        arpDataOut_TLAST => Package_Sender_U0_arpDataOut_TLAST);

    arp_table_U0 : component arp_server_arp_table
    port map (
        ap_clk => ap_clk,
        ap_rst => ap_rst_n_inv,
        ap_start => arp_table_U0_ap_start,
        ap_done => arp_table_U0_ap_done,
        ap_continue => arp_table_U0_ap_continue,
        ap_idle => arp_table_U0_ap_idle,
        ap_ready => arp_table_U0_ap_ready,
        macUpdate_resp_TVALID => macUpdate_resp_TVALID,
        macLookup_resp_TVALID => macLookup_resp_TVALID,
        arpTableInsertFifo_dout => arpTableInsertFifo_dout,
        arpTableInsertFifo_num_data_valid => arpTableInsertFifo_num_data_valid,
        arpTableInsertFifo_fifo_cap => arpTableInsertFifo_fifo_cap,
        arpTableInsertFifo_empty_n => arpTableInsertFifo_empty_n,
        arpTableInsertFifo_read => arp_table_U0_arpTableInsertFifo_read,
        macIpEncode_req_TVALID => macIpEncode_req_TVALID,
        macIpEncode_rsp_TREADY => macIpEncode_rsp_TREADY,
        arpRequestMetaFifo_din => arp_table_U0_arpRequestMetaFifo_din,
        arpRequestMetaFifo_num_data_valid => arpRequestMetaFifo_num_data_valid,
        arpRequestMetaFifo_fifo_cap => arpRequestMetaFifo_fifo_cap,
        arpRequestMetaFifo_full_n => arpRequestMetaFifo_full_n,
        arpRequestMetaFifo_write => arp_table_U0_arpRequestMetaFifo_write,
        macUpdate_req_TREADY => macUpdate_req_TREADY,
        macLookup_req_TREADY => macLookup_req_TREADY,
        macIpEncode_req_TDATA => macIpEncode_req_TDATA,
        macIpEncode_req_TREADY => arp_table_U0_macIpEncode_req_TREADY,
        macIpEncode_rsp_TDATA => arp_table_U0_macIpEncode_rsp_TDATA,
        macIpEncode_rsp_TVALID => arp_table_U0_macIpEncode_rsp_TVALID,
        macLookup_req_TDATA => arp_table_U0_macLookup_req_TDATA,
        macLookup_req_TVALID => arp_table_U0_macLookup_req_TVALID,
        macLookup_resp_TDATA => macLookup_resp_TDATA,
        macLookup_resp_TREADY => arp_table_U0_macLookup_resp_TREADY,
        macUpdate_req_TDATA => arp_table_U0_macUpdate_req_TDATA,
        macUpdate_req_TVALID => arp_table_U0_macUpdate_req_TVALID,
        macUpdate_resp_TDATA => macUpdate_resp_TDATA,
        macUpdate_resp_TREADY => arp_table_U0_macUpdate_resp_TREADY);

    myMacAddress_c_U : component arp_server_fifo_w48_d3_S
    port map (
        clk => ap_clk,
        reset => ap_rst_n_inv,
        if_read_ce => ap_const_logic_1,
        if_write_ce => ap_const_logic_1,
        if_din => entry_proc_U0_myMacAddress_c_din,
        if_full_n => myMacAddress_c_full_n,
        if_write => entry_proc_U0_myMacAddress_c_write,
        if_dout => myMacAddress_c_dout,
        if_num_data_valid => myMacAddress_c_num_data_valid,
        if_fifo_cap => myMacAddress_c_fifo_cap,
        if_empty_n => myMacAddress_c_empty_n,
        if_read => Package_Sender_U0_myMacAddress_read);

    myIpAddress_c_U : component arp_server_fifo_w32_d2_S
    port map (
        clk => ap_clk,
        reset => ap_rst_n_inv,
        if_read_ce => ap_const_logic_1,
        if_write_ce => ap_const_logic_1,
        if_din => Package_Receiver_U0_myIpAddress_c_din,
        if_full_n => myIpAddress_c_full_n,
        if_write => Package_Receiver_U0_myIpAddress_c_write,
        if_dout => myIpAddress_c_dout,
        if_num_data_valid => myIpAddress_c_num_data_valid,
        if_fifo_cap => myIpAddress_c_fifo_cap,
        if_empty_n => myIpAddress_c_empty_n,
        if_read => Package_Sender_U0_myIpAddress_read);

    arpReplyMetaFifo_U : component arp_server_fifo_w192_d4_S
    port map (
        clk => ap_clk,
        reset => ap_rst_n_inv,
        if_read_ce => ap_const_logic_1,
        if_write_ce => ap_const_logic_1,
        if_din => Package_Receiver_U0_arpReplyMetaFifo_din,
        if_full_n => arpReplyMetaFifo_full_n,
        if_write => Package_Receiver_U0_arpReplyMetaFifo_write,
        if_dout => arpReplyMetaFifo_dout,
        if_num_data_valid => arpReplyMetaFifo_num_data_valid,
        if_fifo_cap => arpReplyMetaFifo_fifo_cap,
        if_empty_n => arpReplyMetaFifo_empty_n,
        if_read => Package_Sender_U0_arpReplyMetaFifo_read);

    arpTableInsertFifo_U : component arp_server_fifo_w81_d4_S
    port map (
        clk => ap_clk,
        reset => ap_rst_n_inv,
        if_read_ce => ap_const_logic_1,
        if_write_ce => ap_const_logic_1,
        if_din => Package_Receiver_U0_arpTableInsertFifo_din,
        if_full_n => arpTableInsertFifo_full_n,
        if_write => Package_Receiver_U0_arpTableInsertFifo_write,
        if_dout => arpTableInsertFifo_dout,
        if_num_data_valid => arpTableInsertFifo_num_data_valid,
        if_fifo_cap => arpTableInsertFifo_fifo_cap,
        if_empty_n => arpTableInsertFifo_empty_n,
        if_read => arp_table_U0_arpTableInsertFifo_read);

    arpRequestMetaFifo_U : component arp_server_fifo_w32_d4_S
    port map (
        clk => ap_clk,
        reset => ap_rst_n_inv,
        if_read_ce => ap_const_logic_1,
        if_write_ce => ap_const_logic_1,
        if_din => arp_table_U0_arpRequestMetaFifo_din,
        if_full_n => arpRequestMetaFifo_full_n,
        if_write => arp_table_U0_arpRequestMetaFifo_write,
        if_dout => arpRequestMetaFifo_dout,
        if_num_data_valid => arpRequestMetaFifo_num_data_valid,
        if_fifo_cap => arpRequestMetaFifo_fifo_cap,
        if_empty_n => arpRequestMetaFifo_empty_n,
        if_read => Package_Sender_U0_arpRequestMetaFifo_read);




    Package_Receiver_U0_ap_continue <= ap_const_logic_1;
    Package_Receiver_U0_ap_start <= ap_const_logic_1;
    Package_Sender_U0_ap_continue <= ap_const_logic_1;
    Package_Sender_U0_ap_start <= ap_const_logic_1;

    ap_rst_n_inv_assign_proc : process(ap_rst_n)
    begin
                ap_rst_n_inv <= not(ap_rst_n);
    end process;

    arpDataIn_TREADY <= Package_Receiver_U0_arpDataIn_TREADY;
    arpDataOut_TDATA <= Package_Sender_U0_arpDataOut_TDATA;
    arpDataOut_TKEEP <= Package_Sender_U0_arpDataOut_TKEEP;
    arpDataOut_TLAST <= Package_Sender_U0_arpDataOut_TLAST;
    arpDataOut_TSTRB <= Package_Sender_U0_arpDataOut_TSTRB;
    arpDataOut_TVALID <= Package_Sender_U0_arpDataOut_TVALID;
    arp_table_U0_ap_continue <= ap_const_logic_1;
    arp_table_U0_ap_start <= ap_const_logic_1;
    entry_proc_U0_ap_continue <= ap_const_logic_1;
    entry_proc_U0_ap_start <= ap_const_logic_1;
    macIpEncode_req_TREADY <= arp_table_U0_macIpEncode_req_TREADY;
    macIpEncode_rsp_TDATA <= arp_table_U0_macIpEncode_rsp_TDATA;
    macIpEncode_rsp_TVALID <= arp_table_U0_macIpEncode_rsp_TVALID;
    macLookup_req_TDATA <= arp_table_U0_macLookup_req_TDATA;
    macLookup_req_TVALID <= arp_table_U0_macLookup_req_TVALID;
    macLookup_resp_TREADY <= arp_table_U0_macLookup_resp_TREADY;
    macUpdate_req_TDATA <= arp_table_U0_macUpdate_req_TDATA;
    macUpdate_req_TVALID <= arp_table_U0_macUpdate_req_TVALID;
    macUpdate_resp_TREADY <= arp_table_U0_macUpdate_resp_TREADY;
end behav;
