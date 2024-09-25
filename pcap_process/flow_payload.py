import sys
import os
import pandas as pd
from tqdm import tqdm
import sys
import time

import nfstream
from nfstream import NFStreamer, NFPlugin
import pandas as pd
import os


class DstIpBidirectionalPacketTracker(NFPlugin):
  def __init__(self, window_size,limit,vulnerable_ports_list,http_ports_list):
      super().__init__()
      self.window_size = window_size
      self.limit=limit
      self.vulnerable_ports=vulnerable_ports_list
      self.http_ports=http_ports_list
      self.dst_ip_bidirectional_packet_counts = {}
      self.dst_ip_src2dst_packet_counts = {}
      self.dst_ip_syn_packet_counts = {}
      self.dst_ip_ack_packet_counts = {}
      self.dst_ip_fin_packet_counts = {}
      self.dst_ip_rst_packet_counts = {}
      self.dst_ip_psh_packet_counts = {}
      self.dst_ip_tcp_packet_counts = {}
      self.dst_ip_udp_packet_counts = {}
      self.dst_ip_icmp_packet_counts = {}
      self.dst_ip_bidirectional_duration = {}
      self.dst_ip_dns_port = {}
      self.dst_ip_dns_src_port = {}
      self.dst_ip_vul_ports = {}
      self.dst_ip_http_ports = {}
      self.dst_ip_unique_ports = {}


      self.srcdst_ip_bidirectional_packet_counts = {}
      self.srcdst_ip_src2dst_packet_counts = {}
      self.srcdst_ip_syn_packet_counts = {}
      self.srcdst_ip_ack_packet_counts = {}
      self.srcdst_ip_fin_packet_counts = {}
      self.srcdst_ip_rst_packet_counts = {}
      self.srcdst_ip_psh_packet_counts = {}
      self.srcdst_ip_tcp_packet_counts = {}
      self.srcdst_ip_udp_packet_counts = {}
      self.srcdst_ip_icmp_packet_counts = {}
      self.srcdst_ip_bidirectional_duration = {}
      self.srcdst_ip_dns_port = {}
      self.srcdst_ip_dns_src_port = {}
      self.srcdst_ip_vul_ports = {}
      self.srcdst_ip_http_ports = {}
      self.srcdst_ip_unique_ports = {}
  def on_init(self, packet, flow):
      # Initialize the flow's bidirectional_packet_count
      # flow.udps.bidirectional_packet_count = 0
      # flow.udps.src2dst_packet_count = 0
      # flow.udps.syn_packet_count = 0
      # flow.udps.ack_packet_count = 0
      # flow.udps.rst_packet_count = 0
      # flow.udps.fin_packet_count = 0
      # flow.udps.psh_packet_count = 0
      # flow.udps.tcp_packet_count=0
      # flow.udps.udp_packet_count=0
      # flow.udps.icmp_packet_count=0
      # flow.udps.bidirectional_duration_avg=0
      # flow.udps.dns_port_count=0
      # flow.udps.dns_port_src_count=0
      # # flow.udps.vul_ports_count=0 #*******************************************************************************************************
      # flow.udps.http_ports_count=0
      # # flow.udps.unique_ports_count=0 #***************************************************************************************************
      # flow.udps.packet_size_variation=0


      # #adding source destination
      # flow.udps.srcdst_bidirectional_packet_count = 0
      # flow.udps.srcdst_src2dst_packet_count = 0
      # flow.udps.srcdst_syn_packet_count = 0
      # flow.udps.srcdst_ack_packet_count = 0
      # flow.udps.srcdst_rst_packet_count = 0
      # flow.udps.srcdst_fin_packet_count = 0
      # flow.udps.srcdst_psh_packet_count = 0
      # flow.udps.srcdst_tcp_packet_count=0
      # flow.udps.srcdst_udp_packet_count=0
      # flow.udps.srcdst_icmp_packet_count=0
      # flow.udps.srcdst_bidirectional_duration_avg=0
      # flow.udps.srcdst_dns_port_count=0
      # flow.udps.srcdst_dns_port_src_count=0
      # flow.udps.srcdst_vul_ports_count=0
      # flow.udps.srcdst_http_ports_count=0
      # flow.udps.srcdst_unique_ports_count=0
      # flow.udps.srcdst_packet_size_variation=0


      if self.limit == 1:
          flow.expiration_id = -1

      flow.udps.payload_data = list() ## For Payload of each packet
      if packet.payload_size>0:
        flow.udps.payload_data.append(packet.ip_packet[-packet.payload_size:].hex()) ## First packet time
      else:
        flow.udps.payload_data.append(str('00'))

      flow.udps.delta_time = [] ## Delta_time column
      flow.udps.delta_time.append(packet.delta_time)

      flow.udps.packet_direction =[] ## Packet Direction
      flow.udps.packet_direction.append(packet.direction)  ## Packet Direction

      flow.udps.ip_size = [] ## IP Packet Size
      flow.udps.ip_size.append(packet.ip_size) ## IP Packet Size

      flow.udps.transport_size = [] ## Transport Size
      flow.udps.transport_size.append(packet.transport_size) ## Transport Size

      flow.udps.payload_size = [] ## payload Size
      flow.udps.payload_size.append(packet.payload_size) ## payload Size

      ## Flags in each packet
      flow.udps.syn = [] ## Syn Flag Present
      flow.udps.syn.append(packet.syn)

      flow.udps.cwr = [] ## CWR Flag Present
      flow.udps.cwr.append(packet.cwr)

      flow.udps.ece = [] ## ECE Flag Present
      flow.udps.ece.append(packet.ece)

      flow.udps.urg = [] ## URG Flag Present
      flow.udps.urg.append(packet.urg)

      flow.udps.ack = [] ## ACK Flag Present
      flow.udps.ack.append(packet.ack)

      flow.udps.psh = [] ## PSH Flag Present
      flow.udps.psh.append(packet.psh)

      flow.udps.rst = [] ## RST Flag Present
      flow.udps.rst.append(packet.rst)

      flow.udps.fin = [] ## RST Flag Present
      flow.udps.fin.append(packet.fin)

      #print("Flow_Initiated")
      flow.udps.srcdst_packet_size_variation=0
      flow.udps.srcdst_udp_packet_count=0
      flow.udps.udp_packet_count=0
      flow.udps.srcdst_tcp_packet_count=0
      flow.udps.tcp_packet_count=0
      flow.udps.srcdst_ack_packet_count=0
      flow.udps.ack_packet_count=0
      flow.udps.srcdst_fin_packet_count=0
      flow.udps.fin_packet_count=0
      flow.udps.srcdst_rst_packet_count=0
      flow.udps.rst_packet_count=0
      flow.udps.srcdst_psh_packet_count=0
      flow.udps.psh_packet_count=0
      flow.udps.srcdst_syn_packet_count=0
      flow.udps.syn_packet_count=0
      flow.udps.srcdst_unique_ports_count=0
      flow.udps.srcdst_icmp_packet_count=0
      flow.udps.icmp_packet_count=0
      flow.udps.srcdst_http_ports_count=0
      flow.udps.http_ports_count=0
      flow.udps.srcdst_bidirectional_duration_avg=0
      flow.udps.bidirectional_duration_avg=0
      flow.udps.srcdst_dns_port_count=0
      flow.udps.dns_port_count=0
      flow.udps.srcdst_dns_port_src_count=0
      flow.udps.dns_port_src_count=0
      flow.udps.srcdst_vul_ports_count=0
      flow.udps.src2dst_packet_count=0
      flow.udps.bidirectional_packet_count=0
      flow.udps.srcdst_src2dst_packet_count=0
      flow.udps.srcdst_bidirectional_packet_count=0

  def on_update(self, packet, flow):

      # Increment bidirectional packet count
      #flow.udps.bidirectional_packet_count += 1


      if packet.payload_size>0:
        
        flow.udps.payload_data.append(packet.ip_packet[-packet.payload_size:].hex()) ## Rest of the packet time
        
      else:
        flow.udps.payload_data.append(str('00'))

      flow.udps.delta_time.append(packet.delta_time)  ## Delta_time column

      flow.udps.packet_direction.append(packet.direction)  ## Packet Direction

      flow.udps.ip_size.append(packet.ip_size) ## IP Packet Size

      flow.udps.transport_size.append(packet.transport_size) ## Transport Size

      flow.udps.payload_size.append(packet.payload_size) ## payload Size

      flow.udps.syn.append(packet.syn) ## Syn Flag Present
      flow.udps.cwr.append(packet.cwr) ## CWR Flag Present
      flow.udps.ece.append(packet.ece) ## ECE Flag Present
      flow.udps.urg.append(packet.urg) ## URG Flag Present
      flow.udps.ack.append(packet.ack) ## ACK Flag Present
      flow.udps.psh.append(packet.psh) ## PSH Flag Present
      flow.udps.rst.append(packet.rst) ## RST Flag Present
      flow.udps.fin.append(packet.fin) ## FIN Flag Present

      if self.limit == flow.bidirectional_packets:
        flow.expiration_id = -1 # -1 value force expiration

  def on_expire(self, flow):
      dst_ip = flow.dst_ip
      import numpy as np
      # Update the global dictionary with the count for this destination IP
      if dst_ip in self.dst_ip_bidirectional_packet_counts:
          self.dst_ip_bidirectional_packet_counts[dst_ip].append(flow.bidirectional_packets)
          self.dst_ip_src2dst_packet_counts[dst_ip].append(flow.src2dst_packets)
          self.dst_ip_bidirectional_duration[dst_ip].append(flow.bidirectional_duration_ms)
          self.dst_ip_syn_packet_counts[dst_ip].append(np.array(flow.udps.syn).sum())
          self.dst_ip_ack_packet_counts[dst_ip].append(np.array(flow.udps.ack).sum())
          self.dst_ip_rst_packet_counts[dst_ip].append(np.array(flow.udps.rst).sum())
          self.dst_ip_fin_packet_counts[dst_ip].append(np.array(flow.udps.fin).sum())
          self.dst_ip_psh_packet_counts[dst_ip].append(np.array(flow.udps.psh).sum())
          def check_proto_existence(feature_value,protocol_number):
            if (flow.protocol in protocol_number):
              feature_value.append(1)
            else:
              feature_value.append(0)
          #updating TCP count
          check_proto_existence(self.dst_ip_tcp_packet_counts[dst_ip],protocol_number=[6])
          check_proto_existence(self.dst_ip_udp_packet_counts[dst_ip],protocol_number=[17])
          check_proto_existence(self.dst_ip_icmp_packet_counts[dst_ip],protocol_number=[1])

          def check_dst_port(feature_value,port_number):
            if (flow.dst_port in port_number):
              feature_value.append(1)
            else:
              feature_value.append(0)
          check_dst_port(self.dst_ip_dns_port[dst_ip],port_number=[53])
          # check_dst_port(self.dst_ip_vul_ports[dst_ip],self.vulnerable_ports)
          check_dst_port(self.dst_ip_http_ports[dst_ip],self.http_ports)


          if(flow.src_port==53):
            self.dst_ip_dns_src_port[dst_ip].append(1)
          else:
            self.dst_ip_dns_src_port[dst_ip].append(0)

          # #Unique Ports count
          # if(flow.dst_port not in self.dst_ip_unique_ports[dst_ip]):
          #   self.dst_ip_unique_ports[dst_ip].append(flow.dst_port)

          def manage_window(feature_values):
            if len(feature_values)>self.window_size:
              feature_values.pop(0)

          manage_window(self.dst_ip_bidirectional_packet_counts[dst_ip])
          manage_window(self.dst_ip_src2dst_packet_counts[dst_ip])
          manage_window(self.dst_ip_bidirectional_duration[dst_ip])
          manage_window(self.dst_ip_syn_packet_counts[dst_ip])
          manage_window(self.dst_ip_ack_packet_counts[dst_ip])
          manage_window(self.dst_ip_rst_packet_counts[dst_ip])
          manage_window(self.dst_ip_fin_packet_counts[dst_ip])
          manage_window(self.dst_ip_psh_packet_counts[dst_ip])
          manage_window(self.dst_ip_tcp_packet_counts[dst_ip])
          manage_window(self.dst_ip_udp_packet_counts[dst_ip])
          manage_window(self.dst_ip_icmp_packet_counts[dst_ip])
          manage_window(self.dst_ip_dns_port[dst_ip])
          manage_window(self.dst_ip_dns_src_port[dst_ip])
          # manage_window(self.dst_ip_vul_ports[dst_ip])
          manage_window(self.dst_ip_http_ports[dst_ip])
          # manage_window(self.dst_ip_unique_ports[dst_ip])

      else:
          self.dst_ip_bidirectional_packet_counts[dst_ip] = [flow.bidirectional_packets]
          self.dst_ip_src2dst_packet_counts[dst_ip] = [flow.src2dst_packets]
          self.dst_ip_bidirectional_duration[dst_ip] = [flow.bidirectional_duration_ms]
          self.dst_ip_syn_packet_counts[dst_ip]= [np.array(flow.udps.syn).sum()]
          self.dst_ip_ack_packet_counts[dst_ip]= [np.array(flow.udps.ack).sum()]
          self.dst_ip_rst_packet_counts[dst_ip]= [np.array(flow.udps.rst).sum()]
          self.dst_ip_fin_packet_counts[dst_ip]= [np.array(flow.udps.fin).sum()]
          self.dst_ip_psh_packet_counts[dst_ip]= [np.array(flow.udps.psh).sum()]
          self.dst_ip_tcp_packet_counts[dst_ip] = [0] if flow.protocol != 6 else [1]
          self.dst_ip_udp_packet_counts[dst_ip] = [0] if flow.protocol != 17 else [1]
          self.dst_ip_icmp_packet_counts[dst_ip] = [0] if flow.protocol != 1 else [1]
          self.dst_ip_dns_port[dst_ip] = [0] if flow.dst_port != 53 else [1]
          self.dst_ip_dns_src_port[dst_ip] = [0] if flow.src_port != 53 else [1]
          # self.dst_ip_vul_ports[dst_ip] = [1] if flow.dst_port in self.vulnerable_ports else [0]
          self.dst_ip_http_ports[dst_ip] = [1] if flow.dst_port in self.http_ports else [0]
          # self.dst_ip_unique_ports[dst_ip] =[flow.dst_port]

      #Src_destination features **************************************************************************************************************
      srcdst_ip = flow.dst_ip+flow.src_ip

      # Update the global dictionary with the count for this destination IP
      if srcdst_ip in self.srcdst_ip_bidirectional_packet_counts:
          self.srcdst_ip_bidirectional_packet_counts[srcdst_ip].append(flow.bidirectional_packets)
          self.srcdst_ip_src2dst_packet_counts[srcdst_ip].append(flow.src2dst_packets)
          self.srcdst_ip_bidirectional_duration[srcdst_ip].append(flow.bidirectional_duration_ms)
          self.srcdst_ip_syn_packet_counts[srcdst_ip].append(np.array(flow.udps.syn).sum())
          self.srcdst_ip_ack_packet_counts[srcdst_ip].append(np.array(flow.udps.ack).sum())
          self.srcdst_ip_rst_packet_counts[srcdst_ip].append(np.array(flow.udps.rst).sum())
          self.srcdst_ip_fin_packet_counts[srcdst_ip].append(np.array(flow.udps.fin).sum())
          self.srcdst_ip_psh_packet_counts[srcdst_ip].append(np.array(flow.udps.psh).sum())
          def check_proto_existence(feature_value,protocol_number):
            if (flow.protocol in protocol_number):
              feature_value.append(1)
            else:
              feature_value.append(0)
          #updating TCP count
          check_proto_existence(self.srcdst_ip_tcp_packet_counts[srcdst_ip],protocol_number=[6])
          check_proto_existence(self.srcdst_ip_udp_packet_counts[srcdst_ip],protocol_number=[17])
          check_proto_existence(self.srcdst_ip_icmp_packet_counts[srcdst_ip],protocol_number=[1])

          def check_dst_port(feature_value,port_number):
            if (flow.dst_port in port_number):
              feature_value.append(1)
            else:
              feature_value.append(0)
          check_dst_port(self.srcdst_ip_dns_port[srcdst_ip],port_number=[53])
          check_dst_port(self.srcdst_ip_vul_ports[srcdst_ip],self.vulnerable_ports)
          check_dst_port(self.srcdst_ip_http_ports[srcdst_ip],self.http_ports)


          if(flow.src_port==53):
            self.srcdst_ip_dns_src_port[srcdst_ip].append(1)
          else:
            self.srcdst_ip_dns_src_port[srcdst_ip].append(0)

          #Unique Ports count
          if(flow.dst_port not in self.srcdst_ip_unique_ports[srcdst_ip]):
            self.srcdst_ip_unique_ports[srcdst_ip].append(flow.dst_port)

          def manage_window(feature_values):
            if len(feature_values)>self.window_size:
              feature_values.pop(0)

          manage_window(self.srcdst_ip_bidirectional_packet_counts[srcdst_ip])
          manage_window(self.srcdst_ip_src2dst_packet_counts[srcdst_ip])
          manage_window(self.srcdst_ip_bidirectional_duration[srcdst_ip])
          manage_window(self.srcdst_ip_syn_packet_counts[srcdst_ip])
          manage_window(self.srcdst_ip_ack_packet_counts[srcdst_ip])
          manage_window(self.srcdst_ip_rst_packet_counts[srcdst_ip])
          manage_window(self.srcdst_ip_fin_packet_counts[srcdst_ip])
          manage_window(self.srcdst_ip_psh_packet_counts[srcdst_ip])
          manage_window(self.srcdst_ip_tcp_packet_counts[srcdst_ip])
          manage_window(self.srcdst_ip_udp_packet_counts[srcdst_ip])
          manage_window(self.srcdst_ip_icmp_packet_counts[srcdst_ip])
          manage_window(self.srcdst_ip_dns_port[srcdst_ip])
          manage_window(self.srcdst_ip_dns_src_port[srcdst_ip])
          manage_window(self.srcdst_ip_vul_ports[srcdst_ip])
          manage_window(self.srcdst_ip_http_ports[srcdst_ip])
          manage_window(self.srcdst_ip_unique_ports[srcdst_ip])

      else:
          self.srcdst_ip_bidirectional_packet_counts[srcdst_ip] = [flow.bidirectional_packets]
          self.srcdst_ip_src2dst_packet_counts[srcdst_ip] = [flow.src2dst_packets]
          self.srcdst_ip_bidirectional_duration[srcdst_ip] = [flow.bidirectional_duration_ms]
          self.srcdst_ip_syn_packet_counts[srcdst_ip]= [np.array(flow.udps.syn).sum()]
          self.srcdst_ip_ack_packet_counts[srcdst_ip]= [np.array(flow.udps.ack).sum()]
          self.srcdst_ip_rst_packet_counts[srcdst_ip]= [np.array(flow.udps.rst).sum()]
          self.srcdst_ip_fin_packet_counts[srcdst_ip]= [np.array(flow.udps.fin).sum()]
          self.srcdst_ip_psh_packet_counts[srcdst_ip]= [np.array(flow.udps.psh).sum()]
          self.srcdst_ip_tcp_packet_counts[srcdst_ip] = [0] if flow.protocol != 6 else [1]
          self.srcdst_ip_udp_packet_counts[srcdst_ip] = [0] if flow.protocol != 17 else [1]
          self.srcdst_ip_icmp_packet_counts[srcdst_ip] = [0] if flow.protocol != 1 else [1]
          self.srcdst_ip_dns_port[srcdst_ip] = [0] if flow.dst_port != 53 else [1]
          self.srcdst_ip_dns_src_port[srcdst_ip] = [0] if flow.src_port != 53 else [1]
          self.srcdst_ip_vul_ports[srcdst_ip] = [1] if flow.dst_port in self.vulnerable_ports else [0]
          self.srcdst_ip_http_ports[srcdst_ip] = [1] if flow.dst_port in self.http_ports else [0]
          self.srcdst_ip_unique_ports[srcdst_ip] =[flow.dst_port]


      #final update
      # flow.udps.bidirectional_packet_count=np.array(self.dst_ip_bidirectional_packet_counts[dst_ip]).sum()
      # flow.udps.src2dst_packet_count=np.array(self.dst_ip_src2dst_packet_counts[dst_ip]).sum()
      # flow.udps.bidirectional_duration_avg=np.array(self.dst_ip_bidirectional_duration[dst_ip]).mean()
      # flow.udps.syn_packet_count=np.array(self.dst_ip_syn_packet_counts[dst_ip]).sum()
      # flow.udps.ack_packet_count=np.array(self.dst_ip_ack_packet_counts[dst_ip]).sum()
      # flow.udps.rst_packet_count=np.array(self.dst_ip_rst_packet_counts[dst_ip]).sum()
      # flow.udps.fin_packet_count=np.array(self.dst_ip_fin_packet_counts[dst_ip]).sum()
      # flow.udps.psh_packet_count=np.array(self.dst_ip_psh_packet_counts[dst_ip]).sum()
      # flow.udps.tcp_packet_count=np.array(self.dst_ip_tcp_packet_counts[dst_ip]).sum()
      # flow.udps.udp_packet_count=np.array(self.dst_ip_udp_packet_counts[dst_ip]).sum()
      # flow.udps.icmp_packet_count=np.array(self.dst_ip_icmp_packet_counts[dst_ip]).sum()
      # flow.udps.dns_port_count=np.array(self.dst_ip_dns_port[dst_ip]).sum()
      # flow.udps.dns_port_src_count=np.array(self.dst_ip_dns_src_port[dst_ip]).sum()
      ## flow.udps.vul_ports_count=np.array(self.dst_ip_vul_ports[dst_ip]).sum()
      # flow.udps.http_ports_count=np.array(self.dst_ip_http_ports[dst_ip]).sum()
      ## flow.udps.unique_ports_count=len(self.dst_ip_unique_ports[dst_ip])
      #flow.udps.packet_size_variation=(np.std(np.array([flow.src2dst_min_ps,flow.src2dst_max_ps,flow.dst2src_min_ps,flow.dst2src_max_ps]),ddof=1))

      ## src destination update
      # flow.udps.srcdst_bidirectional_packet_count=np.array(self.dst_ip_bidirectional_packet_counts[srcdst_ip]).sum()
      # flow.udps.srcdst_src2dst_packet_count=np.array(self.dst_ip_src2dst_packet_counts[srcdst_ip]).sum()
      # flow.udps.srcdst_bidirectional_duration_avg=np.array(self.dst_ip_bidirectional_duration[srcdst_ip]).mean()
      # flow.udps.srcdst_syn_packet_count=np.array(self.dst_ip_syn_packet_counts[srcdst_ip]).sum()
      # flow.udps.srcdst_ack_packet_count=np.array(self.dst_ip_ack_packet_counts[srcdst_ip]).sum()
      # flow.udps.srcdst_rst_packet_count=np.array(self.dst_ip_rst_packet_counts[srcdst_ip]).sum()
      # flow.udps.srcdst_fin_packet_count=np.array(self.dst_ip_fin_packet_counts[srcdst_ip]).sum()
      # flow.udps.srcdst_psh_packet_count=np.array(self.dst_ip_psh_packet_counts[srcdst_ip]).sum()
      # flow.udps.srcdst_tcp_packet_count=np.array(self.dst_ip_tcp_packet_counts[srcdst_ip]).sum()
      #flow.udps.srcdst_udp_packet_count=np.array(self.dst_ip_udp_packet_counts[srcdst_ip]).sum()
      # flow.udps.srcdst_icmp_packet_count=np.array(self.dst_ip_icmp_packet_counts[srcdst_ip]).sum()
      # flow.udps.srcdst_dns_port_count=np.array(self.dst_ip_dns_port[srcdst_ip]).sum()
      # flow.udps.srcdst_dns_port_src_count=np.array(self.dst_ip_dns_src_port[srcdst_ip]).sum()
      # flow.udps.srcdst_vul_ports_count=np.array(self.dst_ip_vul_ports[srcdst_ip]).sum()
      # flow.udps.srcdst_http_ports_count=np.array(self.dst_ip_http_ports[srcdst_ip]).sum()
      # flow.udps.srcdst_unique_ports_count=len(self.dst_ip_unique_ports[srcdst_ip])


      flow.udps.srcdst_packet_size_variation=(np.std(np.array([flow.src2dst_min_ps,flow.src2dst_max_ps,flow.dst2src_min_ps,flow.dst2src_max_ps]),ddof=1))
      flow.udps.srcdst_udp_packet_count=np.array(self.srcdst_ip_udp_packet_counts[srcdst_ip]).sum()
      flow.udps.udp_packet_count=np.array(self.dst_ip_udp_packet_counts[dst_ip]).sum()
      flow.udps.srcdst_tcp_packet_count=np.array(self.srcdst_ip_tcp_packet_counts[srcdst_ip]).sum()
      flow.udps.tcp_packet_count=np.array(self.dst_ip_tcp_packet_counts[dst_ip]).sum()
      flow.udps.srcdst_ack_packet_count=np.array(self.srcdst_ip_ack_packet_counts[srcdst_ip]).sum()
      flow.udps.ack_packet_count=np.array(self.dst_ip_ack_packet_counts[dst_ip]).sum()
      flow.udps.srcdst_fin_packet_count=np.array(self.srcdst_ip_fin_packet_counts[srcdst_ip]).sum()
      flow.udps.fin_packet_count=np.array(self.dst_ip_fin_packet_counts[dst_ip]).sum()
      flow.udps.srcdst_rst_packet_count=np.array(self.srcdst_ip_rst_packet_counts[srcdst_ip]).sum()
      flow.udps.rst_packet_count=np.array(self.dst_ip_rst_packet_counts[dst_ip]).sum()
      flow.udps.srcdst_psh_packet_count=np.array(self.srcdst_ip_psh_packet_counts[srcdst_ip]).sum()
      flow.udps.psh_packet_count=np.array(self.dst_ip_psh_packet_counts[dst_ip]).sum()
      flow.udps.srcdst_syn_packet_count=np.array(self.srcdst_ip_syn_packet_counts[srcdst_ip]).sum()
      flow.udps.syn_packet_count=np.array(self.dst_ip_syn_packet_counts[dst_ip]).sum()
      flow.udps.srcdst_unique_ports_count=len(self.srcdst_ip_unique_ports[srcdst_ip])
      flow.udps.srcdst_icmp_packet_count=np.array(self.srcdst_ip_icmp_packet_counts[srcdst_ip]).sum()
      flow.udps.icmp_packet_count=np.array(self.dst_ip_icmp_packet_counts[dst_ip]).sum()
      flow.udps.srcdst_http_ports_count=np.array(self.srcdst_ip_http_ports[srcdst_ip]).sum()
      flow.udps.http_ports_count=np.array(self.dst_ip_http_ports[dst_ip]).sum()
      flow.udps.srcdst_bidirectional_duration_avg=np.array(self.srcdst_ip_bidirectional_duration[srcdst_ip]).mean()
      flow.udps.bidirectional_duration_avg=np.array(self.dst_ip_bidirectional_duration[dst_ip]).mean()
      flow.udps.srcdst_dns_port_count=np.array(self.srcdst_ip_dns_port[srcdst_ip]).sum()
      flow.udps.dns_port_count=np.array(self.dst_ip_dns_port[dst_ip]).sum()
      flow.udps.srcdst_dns_port_src_count=np.array(self.srcdst_ip_dns_src_port[srcdst_ip]).sum()
      flow.udps.dns_port_src_count=np.array(self.dst_ip_dns_src_port[dst_ip]).sum()
      flow.udps.srcdst_vul_ports_count=np.array(self.srcdst_ip_vul_ports[srcdst_ip]).sum()
      flow.udps.src2dst_packet_count=np.array(self.dst_ip_src2dst_packet_counts[dst_ip]).sum()
      flow.udps.bidirectional_packet_count=np.array(self.dst_ip_bidirectional_packet_counts[dst_ip]).sum()
      flow.udps.srcdst_src2dst_packet_count=np.array(self.srcdst_ip_src2dst_packet_counts[srcdst_ip]).sum()
      flow.udps.srcdst_bidirectional_packet_count=np.array(self.srcdst_ip_bidirectional_packet_counts[srcdst_ip]).sum()

      #print(flow.udps.bidirectional_packet_count)
      #print('abc')# Print to check the current state of the dictionary
      #print(f"Flow expired for dst_ip: {dst_ip},{flow.src2dst_min_ps,flow.src2dst_max_ps,flow.dst2src_min_ps,flow.dst2src_max_ps} bidirectional_packet_counts: , Final : {flow.udps.packet_size_variation}")


def extract_explainable_features(file_name,window_size,
                                 flow_limit=sys.maxsize, 
                                 vulnerable_ports_list=[20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080],
                                 http_ports_list=[80,443,8080] ,
                                 n_meters=1,active_timeout=1800,idle_timeout=120):
 
  return nfstream.NFStreamer(source=file_name,statistical_analysis=True,n_meters=n_meters,idle_timeout=idle_timeout,active_timeout=active_timeout,
                                    udps=[DstIpBidirectionalPacketTracker(window_size,flow_limit,vulnerable_ports_list,http_ports_list)])






def pcap_process(dataset_folder, window_size, vulnerable_ports_list, http_ports_list, n_meters=1, output_directory=None,
                 active_timeout=1800, idle_timeout=120, flow_limit=sys.maxsize):
    
    # Create the 'processed' folder if it doesn't exist
    if output_directory is None:
        output_directory = os.path.join(dataset_folder, "processed")
    os.makedirs(output_directory, exist_ok=True)

    # Recursively get a list of all pcap files in the folder and subfolders
    file_list = []
    for root, dirs, files in os.walk(dataset_folder):
        for file in files:
            if file.endswith(".pcap"):
                file_list.append(os.path.join(root, file))

    # Process each file with a progress bar
    for file_path in tqdm(file_list, desc="Processing files"):
        try:
            # Check if the file exists
            if not os.path.exists(file_path):
                print(f"File not found: {file_path}")
                continue
            
            # Extract features using `extract_explainable_features`
            try:
                stream_reader = extract_explainable_features(file_path, window_size, flow_limit, 
                                                             vulnerable_ports_list=vulnerable_ports_list,
                                                             http_ports_list=http_ports_list, n_meters=n_meters,
                                                             active_timeout=active_timeout, idle_timeout=idle_timeout)
                
                # Generate output file name
                file_name = os.path.basename(file_path).replace('.pcap', '')
                output_file_name = f"{file_name}_processed.csv"
                output_file_path = os.path.join(output_directory, output_file_name)
                
                # Check if a file with the same name already exists
                if os.path.exists(output_file_path):
                    # Append unique information to avoid overwriting
                    file_size = os.path.getsize(file_path)
                    current_time = time.strftime("%Y%m%d-%H%M%S")
                    output_file_name = f"{file_name}_{file_size}_{current_time}_processed.csv"
                    output_file_path = os.path.join(output_directory, output_file_name)
                file_size = os.path.getsize(file_path)
                # If file size is greater than 2 GB, split into smaller files using nfstream's `rotate_files`
                file_size_gb = file_size / (1024 ** 3)  # Convert bytes to GB
                #print(file_size_gb)
                
                
                
                if file_size_gb > 2:
                    
                    stream_reader.to_csv(path=output_file_path, columns_to_anonymize=[], flows_per_file=100000, rotate_files=200)
                    print(f"Processed and split large file {file_path} into smaller CSVs.")
                else:
                    # For smaller files, process and write to a single CSV
                    df = stream_reader.to_pandas()
                    df['file'] = os.path.basename(file_path)
                    df.to_csv(output_file_path, index=False)
                    print(f"Processed and saved {output_file_path}")
                
            except Exception as e:
                print(f"Failed to process file: {file_path}. Error: {e}")
    
        except Exception as e:
            print(f"An error occurred with file: {file_path}. Error: {e}")

    print(f"All files processed and saved in {output_directory}")
    
    return "Status: Completed"
