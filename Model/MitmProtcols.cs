using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PacketDotNet;
using SharpPcap;

namespace Ng_IDS.Model
{
    class MitmProtcols
    {
       
        public static string  GetMitmProtocol(CaptureEventArgs e)
        {
            var mypacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var arp = (ARPPacket)mypacket.Extract(typeof(ARPPacket));
            var udp = (UdpPacket)mypacket.Extract(typeof(UdpPacket));
            if (arp != null)
            {
                 return "ARP";
            }
            if (udp != null)
            {
                if (udp.DestinationPort == 67 && udp.DestinationPort == 68)
                {
                    return  "DHCP";
                }
            }
            return "";
        }

        public static int GetArpTrafic(CaptureEventArgs e)
        {
            var mypacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var arp = (ARPPacket)mypacket.Extract(typeof(ARPPacket));
            int num = 0;

            if (arp != null)
            {
                num++;
                return num++;
            }
            return 0;
        }

        public static int GetDhcpTrafic(CaptureEventArgs e)
        {
            var mypacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var udp = (UdpPacket)mypacket.Extract(typeof(UdpPacket));
            int num = 0;
            if (udp != null)
            {
                if (udp.DestinationPort == 67 && udp.DestinationPort == 68)
                {
                    num++;
                    return num;
                }
            }
            return 0;
        }

        public static int GetUdpTrafic(CaptureEventArgs e)
        {
            var mypacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var udp = (UdpPacket)mypacket.Extract(typeof(UdpPacket));
            int num = 0;
            if (udp != null)
            {
                    num++;
                    return num;
               
            }
            return 0;
        }

        public static int GetTCPTrafic(CaptureEventArgs e)
        {
            var mypacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcp = (TcpPacket)mypacket.Extract(typeof(TcpPacket));
            int num = 0;
            if (tcp != null)
            {
                num++;
                return num;

            }
            return 0;
        }

        public static int GetIcmpTrafic(CaptureEventArgs e)
        {
            var mypacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var icmp = (ICMPv4Packet)mypacket.Extract(typeof(ICMPv4Packet));
            int num = 0;
            if (icmp != null)
            {
                num++;
                return num++;

            }
            return 0;
        }
    }
}
