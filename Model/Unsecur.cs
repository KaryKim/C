using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PacketDotNet;

namespace Ng_IDS.Model
{
    class Unsecur
    {
        public String GetUNsecurTcp(TcpPacket tcp)
        {
            if (tcp.DestinationPort == 80)
            {
                return "HTTP";
            }
            else if (tcp.DestinationPort == 21)
            {
                return "FTP";
            }
            else if (tcp.DestinationPort == 143)
            {
                return "IMAP";
            }
            else if (tcp.DestinationPort == 25)
            {
                return "SMTP";
            }
            else if (tcp.DestinationPort == 110)
            {
                return "POP3";
            }
            return "";
        }
    }
}
