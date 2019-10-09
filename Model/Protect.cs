using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Net;

namespace Ng_IDS.Model
{
    class Protect
    {
        public static EthernetPacket Protect_Arp(string Router_mac,string My_pc_mac,string Router_ip,string My_pc_ip)
        {
            var eth = new EthernetPacket(PhysicalAddress.Parse(Router_mac),PhysicalAddress.Parse(My_pc_mac), EthernetPacketType.Arp);
            var arp = new ARPPacket(ARPOperation.Response, PhysicalAddress.Parse(My_pc_mac), IPAddress.Parse(My_pc_ip), PhysicalAddress.Parse(Router_mac), IPAddress.Parse(Router_ip));
            eth.PayloadPacket = arp;
            return eth;
        }
    }
}
