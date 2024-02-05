-- ==============================================================
-- Generated by Vitis HLS v2023.2.1
-- Copyright 1986-2022 Xilinx, Inc. All Rights Reserved.
-- Copyright 2022-2023 Advanced Micro Devices, Inc. All Rights Reserved.
-- ==============================================================

library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.numeric_std.all;

entity packet_handler is
port (
    s_axis_TDATA : IN STD_LOGIC_VECTOR (1023 downto 0);
    m_axis_TDATA : OUT STD_LOGIC_VECTOR (1023 downto 0);
    ap_clk : IN STD_LOGIC;
    ap_rst_n : IN STD_LOGIC;
    s_axis_TVALID : IN STD_LOGIC;
    s_axis_TREADY : OUT STD_LOGIC;
    m_axis_TVALID : OUT STD_LOGIC;
    m_axis_TREADY : IN STD_LOGIC );
end;


architecture behav of packet_handler is 
    attribute CORE_GENERATION_INFO : STRING;
    attribute CORE_GENERATION_INFO of behav : architecture is
    "packet_handler_packet_handler,hls_ip_2023_2_1,{HLS_INPUT_TYPE=cxx,HLS_INPUT_FLOAT=0,HLS_INPUT_FIXED=0,HLS_INPUT_PART=xcku5p-ffvb676-2-e,HLS_INPUT_CLOCK=10.000000,HLS_INPUT_ARCH=dataflow,HLS_SYN_CLOCK=4.315625,HLS_SYN_LAT=4,HLS_SYN_TPT=1,HLS_SYN_MEM=57,HLS_SYN_DSP=0,HLS_SYN_FF=4258,HLS_SYN_LUT=1643,HLS_VERSION=2023_2_1}";
    constant ap_const_logic_1 : STD_LOGIC := '1';
    constant ap_const_logic_0 : STD_LOGIC := '0';

    signal ap_rst_n_inv : STD_LOGIC;
    signal packet_identification_U0_ap_start : STD_LOGIC;
    signal packet_identification_U0_ap_done : STD_LOGIC;
    signal packet_identification_U0_ap_continue : STD_LOGIC;
    signal packet_identification_U0_ap_idle : STD_LOGIC;
    signal packet_identification_U0_ap_ready : STD_LOGIC;
    signal packet_identification_U0_eth_level_pkt_din : STD_LOGIC_VECTOR (1023 downto 0);
    signal packet_identification_U0_eth_level_pkt_write : STD_LOGIC;
    signal packet_identification_U0_start_out : STD_LOGIC;
    signal packet_identification_U0_start_write : STD_LOGIC;
    signal packet_identification_U0_s_axis_TREADY : STD_LOGIC;
    signal ethernet_remover_U0_ap_start : STD_LOGIC;
    signal ethernet_remover_U0_ap_done : STD_LOGIC;
    signal ethernet_remover_U0_ap_continue : STD_LOGIC;
    signal ethernet_remover_U0_ap_idle : STD_LOGIC;
    signal ethernet_remover_U0_ap_ready : STD_LOGIC;
    signal ethernet_remover_U0_eth_level_pkt_read : STD_LOGIC;
    signal ethernet_remover_U0_m_axis_TDATA : STD_LOGIC_VECTOR (1023 downto 0);
    signal ethernet_remover_U0_m_axis_TVALID : STD_LOGIC;
    signal eth_level_pkt_full_n : STD_LOGIC;
    signal eth_level_pkt_dout : STD_LOGIC_VECTOR (1023 downto 0);
    signal eth_level_pkt_num_data_valid : STD_LOGIC_VECTOR (4 downto 0);
    signal eth_level_pkt_fifo_cap : STD_LOGIC_VECTOR (4 downto 0);
    signal eth_level_pkt_empty_n : STD_LOGIC;
    signal start_for_ethernet_remover_U0_din : STD_LOGIC_VECTOR (0 downto 0);
    signal start_for_ethernet_remover_U0_full_n : STD_LOGIC;
    signal start_for_ethernet_remover_U0_dout : STD_LOGIC_VECTOR (0 downto 0);
    signal start_for_ethernet_remover_U0_empty_n : STD_LOGIC;

    component packet_handler_packet_identification IS
    port (
        ap_clk : IN STD_LOGIC;
        ap_rst : IN STD_LOGIC;
        ap_start : IN STD_LOGIC;
        start_full_n : IN STD_LOGIC;
        ap_done : OUT STD_LOGIC;
        ap_continue : IN STD_LOGIC;
        ap_idle : OUT STD_LOGIC;
        ap_ready : OUT STD_LOGIC;
        s_axis_TVALID : IN STD_LOGIC;
        eth_level_pkt_din : OUT STD_LOGIC_VECTOR (1023 downto 0);
        eth_level_pkt_num_data_valid : IN STD_LOGIC_VECTOR (4 downto 0);
        eth_level_pkt_fifo_cap : IN STD_LOGIC_VECTOR (4 downto 0);
        eth_level_pkt_full_n : IN STD_LOGIC;
        eth_level_pkt_write : OUT STD_LOGIC;
        start_out : OUT STD_LOGIC;
        start_write : OUT STD_LOGIC;
        s_axis_TDATA : IN STD_LOGIC_VECTOR (1023 downto 0);
        s_axis_TREADY : OUT STD_LOGIC );
    end component;


    component packet_handler_ethernet_remover IS
    port (
        ap_clk : IN STD_LOGIC;
        ap_rst : IN STD_LOGIC;
        ap_start : IN STD_LOGIC;
        ap_done : OUT STD_LOGIC;
        ap_continue : IN STD_LOGIC;
        ap_idle : OUT STD_LOGIC;
        ap_ready : OUT STD_LOGIC;
        eth_level_pkt_dout : IN STD_LOGIC_VECTOR (1023 downto 0);
        eth_level_pkt_num_data_valid : IN STD_LOGIC_VECTOR (4 downto 0);
        eth_level_pkt_fifo_cap : IN STD_LOGIC_VECTOR (4 downto 0);
        eth_level_pkt_empty_n : IN STD_LOGIC;
        eth_level_pkt_read : OUT STD_LOGIC;
        m_axis_TREADY : IN STD_LOGIC;
        m_axis_TDATA : OUT STD_LOGIC_VECTOR (1023 downto 0);
        m_axis_TVALID : OUT STD_LOGIC );
    end component;


    component packet_handler_fifo_w1024_d16_A IS
    port (
        clk : IN STD_LOGIC;
        reset : IN STD_LOGIC;
        if_read_ce : IN STD_LOGIC;
        if_write_ce : IN STD_LOGIC;
        if_din : IN STD_LOGIC_VECTOR (1023 downto 0);
        if_full_n : OUT STD_LOGIC;
        if_write : IN STD_LOGIC;
        if_dout : OUT STD_LOGIC_VECTOR (1023 downto 0);
        if_num_data_valid : OUT STD_LOGIC_VECTOR (4 downto 0);
        if_fifo_cap : OUT STD_LOGIC_VECTOR (4 downto 0);
        if_empty_n : OUT STD_LOGIC;
        if_read : IN STD_LOGIC );
    end component;


    component packet_handler_start_for_ethernet_remover_U0 IS
    port (
        clk : IN STD_LOGIC;
        reset : IN STD_LOGIC;
        if_read_ce : IN STD_LOGIC;
        if_write_ce : IN STD_LOGIC;
        if_din : IN STD_LOGIC_VECTOR (0 downto 0);
        if_full_n : OUT STD_LOGIC;
        if_write : IN STD_LOGIC;
        if_dout : OUT STD_LOGIC_VECTOR (0 downto 0);
        if_empty_n : OUT STD_LOGIC;
        if_read : IN STD_LOGIC );
    end component;



begin
    packet_identification_U0 : component packet_handler_packet_identification
    port map (
        ap_clk => ap_clk,
        ap_rst => ap_rst_n_inv,
        ap_start => packet_identification_U0_ap_start,
        start_full_n => start_for_ethernet_remover_U0_full_n,
        ap_done => packet_identification_U0_ap_done,
        ap_continue => packet_identification_U0_ap_continue,
        ap_idle => packet_identification_U0_ap_idle,
        ap_ready => packet_identification_U0_ap_ready,
        s_axis_TVALID => s_axis_TVALID,
        eth_level_pkt_din => packet_identification_U0_eth_level_pkt_din,
        eth_level_pkt_num_data_valid => eth_level_pkt_num_data_valid,
        eth_level_pkt_fifo_cap => eth_level_pkt_fifo_cap,
        eth_level_pkt_full_n => eth_level_pkt_full_n,
        eth_level_pkt_write => packet_identification_U0_eth_level_pkt_write,
        start_out => packet_identification_U0_start_out,
        start_write => packet_identification_U0_start_write,
        s_axis_TDATA => s_axis_TDATA,
        s_axis_TREADY => packet_identification_U0_s_axis_TREADY);

    ethernet_remover_U0 : component packet_handler_ethernet_remover
    port map (
        ap_clk => ap_clk,
        ap_rst => ap_rst_n_inv,
        ap_start => ethernet_remover_U0_ap_start,
        ap_done => ethernet_remover_U0_ap_done,
        ap_continue => ethernet_remover_U0_ap_continue,
        ap_idle => ethernet_remover_U0_ap_idle,
        ap_ready => ethernet_remover_U0_ap_ready,
        eth_level_pkt_dout => eth_level_pkt_dout,
        eth_level_pkt_num_data_valid => eth_level_pkt_num_data_valid,
        eth_level_pkt_fifo_cap => eth_level_pkt_fifo_cap,
        eth_level_pkt_empty_n => eth_level_pkt_empty_n,
        eth_level_pkt_read => ethernet_remover_U0_eth_level_pkt_read,
        m_axis_TREADY => m_axis_TREADY,
        m_axis_TDATA => ethernet_remover_U0_m_axis_TDATA,
        m_axis_TVALID => ethernet_remover_U0_m_axis_TVALID);

    eth_level_pkt_U : component packet_handler_fifo_w1024_d16_A
    port map (
        clk => ap_clk,
        reset => ap_rst_n_inv,
        if_read_ce => ap_const_logic_1,
        if_write_ce => ap_const_logic_1,
        if_din => packet_identification_U0_eth_level_pkt_din,
        if_full_n => eth_level_pkt_full_n,
        if_write => packet_identification_U0_eth_level_pkt_write,
        if_dout => eth_level_pkt_dout,
        if_num_data_valid => eth_level_pkt_num_data_valid,
        if_fifo_cap => eth_level_pkt_fifo_cap,
        if_empty_n => eth_level_pkt_empty_n,
        if_read => ethernet_remover_U0_eth_level_pkt_read);

    start_for_ethernet_remover_U0_U : component packet_handler_start_for_ethernet_remover_U0
    port map (
        clk => ap_clk,
        reset => ap_rst_n_inv,
        if_read_ce => ap_const_logic_1,
        if_write_ce => ap_const_logic_1,
        if_din => start_for_ethernet_remover_U0_din,
        if_full_n => start_for_ethernet_remover_U0_full_n,
        if_write => packet_identification_U0_start_write,
        if_dout => start_for_ethernet_remover_U0_dout,
        if_empty_n => start_for_ethernet_remover_U0_empty_n,
        if_read => ethernet_remover_U0_ap_ready);





    ap_rst_n_inv_assign_proc : process(ap_rst_n)
    begin
                ap_rst_n_inv <= not(ap_rst_n);
    end process;

    ethernet_remover_U0_ap_continue <= ap_const_logic_1;
    ethernet_remover_U0_ap_start <= start_for_ethernet_remover_U0_empty_n;
    m_axis_TDATA <= ethernet_remover_U0_m_axis_TDATA;
    m_axis_TVALID <= ethernet_remover_U0_m_axis_TVALID;
    packet_identification_U0_ap_continue <= ap_const_logic_1;
    packet_identification_U0_ap_start <= ap_const_logic_1;
    s_axis_TREADY <= packet_identification_U0_s_axis_TREADY;
    start_for_ethernet_remover_U0_din <= (0=>ap_const_logic_1, others=>'-');
end behav;