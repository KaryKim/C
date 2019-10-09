using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpPcap.WinPcap;
using SharpPcap;
using System.Data;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Net;
using Ng_IDS.Model;
using System.Threading;
using System.Runtime.InteropServices;
using System.Net.Sockets;
using System.IO;
using System.Collections;

namespace Open_HIDS
{
    class Program
    {

        static int devIndex;
        static public string gat { get; set; }
        static public string Hip { get; set; }
        static public string Hmac { get; set; }                                          
        static public string Hinter { get; set; }
        static public string Hdefullt { get; set; }
        static public string Rip { get; set; }
        static public string Rmac { get; set; }
        static public bool RunArp { get; set; }
        static public bool RunDhcp { get; set; }
        static public bool RunAll { get; set; }
        static public bool scan { get; set; }
  
        static string commend;
        public static int num { get; set; }
        static void Main(string[] args)
        {
          
            Console.WriteLine(Environment.NewLine);
            Console.Title = "入侵检测系统";
            Console.WriteLine(@"");
            Console.WriteLine(@"计算机1621 ");
            Console.WriteLine(@"1630107137  陈灿婷");
            Console.WriteLine(@"入侵检测系统的设计与实现");


            Console.WriteLine(Environment.NewLine);
      
            if (!File.Exists("data.sqlite"))
            {
                ado o = new ado();
                o.creatDB();
                
            }
            if (!File.Exists("ports.port"))
            {
                create_file();
            }
         
            try
            {
               var devic = WinPcapDeviceList.Instance;
            }
            catch (Exception)
            {

                Console.WriteLine("没有发现接口!确保在本地机器上正确安装libpcap /WinPcap.");
               Thread.Sleep(5000);
                 return;
            }
            var devices = WinPcapDeviceList.Instance;


          
            if (devices.Count < 1)
            {
                Console.WriteLine("在这台机器上没有发现任何设备，请确认你已经安装了winpcap");
                return;
            }

            Console.WriteLine("请选择一个选项*** :");
            Console.WriteLine("********************************");
            Console.WriteLine();

            int i = 0;

            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1}", i, dev.Description);
                Console.WriteLine(Environment.NewLine);
                i++;
            }

            Console.WriteLine();
            Console.Write("***请选择一个选项***: ");

            i = int.Parse(Console.ReadLine());
            



            devIndex = i;
            if (devices.Count < i)
            {
                Console.WriteLine("***{0} 是不正确的*** : ", i.ToString());
                Console.WriteLine("***请选择一个选项*** : ");
                i = int.Parse(Console.ReadLine());
                if (devices.Count < i)
                {
                    return;
                }
                // ;
            }

            
            var device = devices[i];
          
         
            device.Open(DeviceMode.Promiscuous, 1000);
        
            num = 0;
            foreach (var item in device.Addresses)
            {
                if (item.Addr.ipAddress != null)
                {
               
                    if (item.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        int inf = Array.IndexOf(device.Addresses.ToArray(), item);
                        num = inf;
                    }
                }

            }
            Console.WriteLine(Environment.NewLine);
            Console.WriteLine("界面 : {0}", device.Description);
        

            Hip = device.Addresses[num].Addr.ToString();
            Hmac = device.MacAddress.ToString();
           
            if (device.Interface.GatewayAddress == null)
            {

                Console.WriteLine("你没有GatewayAddress");
                Console.ReadKey();
                return;
            }
            gat = device.Interface.GatewayAddress.ToString();
            Hdefullt = device.Interface.GatewayAddress.ToString();
            Hinter = device.Description.Replace("'", "");
            Console.WriteLine(Environment.NewLine); 
            Console.WriteLine("IP Address : {0}",device.Addresses[num].Addr);
            Console.WriteLine(Environment.NewLine);
            Console.WriteLine("MAC Address : {0}",device.MacAddress.ToString());
            if (IPAddress.Parse(gat).AddressFamily == AddressFamily.InterNetworkV6)
            {
                Console.WriteLine("Catch不能找到你的网关地址，请输入你的网关地址 : ");
                var g = Console.ReadLine();
      
  
                gat = g; 
            }
            

            Console.WriteLine(Environment.NewLine);
            Console.WriteLine("Defult Gatway : {0}",gat);
            Console.WriteLine(Environment.NewLine);
            Console.WriteLine("__________________________Router_______________________________");
            Console.WriteLine("Router IP Address : {0}", gat);
            
        

            string myip = device.Addresses[num].Addr.ToString();

            try
            {
                IPAddress address = IPAddress.Parse(gat);
            }
            catch (Exception ex)
            {

                Console.WriteLine(ex.Message + " " + gat);
                Thread.Sleep(3000);
                return;
                
            }
            if (string.IsNullOrEmpty(gat)!= null)
            {
                    EthernetPacket eth = Protect_Arp(device.MacAddress.ToString(), "FFFFFFFFFFFF", myip, gat);
                    device.SendPacket(eth);
            }

            Thread th = new Thread(() => {
            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);
            });
            th.Start();
            Rmac = getGAtWatWayMac(device,gat);
            if (Rmac == "")
            {
                Console.WriteLine("您没有连接到路由器，重新尝试");
                
                Console.ReadKey();
                return;
                
            }
           
            Console.WriteLine("Router MAC Address : {0}", Rmac);

            Rip = gat;

            device.StartCapture();
          
            Console.WriteLine(Environment.NewLine);



       
            ado a = new ado();
            if (a.checkpc(Hip,Hmac,Hinter).Rows.Count > 0)
            {
                
            }
            else
            {
                Data d = new Data() { date = DateTime.Now.ToString(), inter = Hinter, name="Pc", ip= Hip, mac=Hmac };
                a.insert(d);
            }

            if (a.selectname("Router", Hinter).Rows.Count > 0)
            {
                int id = 0;                
                DataTable dt = a.selectname("Router", Hinter);
                
                foreach (DataRow  item in dt.Rows)
                {
                    string ip = item[4].ToString();
                    string mac = item[3].ToString();
                    string Time = item[5].ToString();
                    id = Convert.ToInt32(item[0]);
                    if (mac == Rmac)
                    {
                        
                      
                    }
                    else
                    {
                        
                        cheeck(new ado(),ip, mac, Time, id);
                    }

                    
                }


               
                

            }
            else 
            {
                Data d = new Data() { inter = Hinter, date= DateTime.Now.ToString(), ip = Rip, mac = Rmac, name = "Router"};
                a.insert(d);
            }

            Runcmd();


        }

        static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
        
                scan s = new scan();
                if (RunArp == true)
                {
                    s.ScanAttack(e, Hinter,Rip);
                }
                if (RunDhcp == true)
                {
                    s.ScanDhcp(e, Hinter);
                }
                if (s.Attack == true)
                {
                    for (int i = 0; i < 3; i++)
                    {
                        System.Media.SystemSounds.Hand.Play();
                        Console.WriteLine("********************* You Have Been Attacked **************************");
                        Console.WriteLine(Environment.NewLine);
                        Console.WriteLine("Attack Name : {0} , Time : {1} , Attacker HardwareAddress : {2} , Attacker ip address : {3} ", s.Attack_data[0], s.Attack_data[3], s.Attack_data[2], s.Attack_data[1]);
                        Console.WriteLine(Environment.NewLine);
                        Console.WriteLine("Old data  {0} {1} {2} {3}  ", s.Attack_data[4], s.Attack_data[5], s.Attack_data[6], s.Attack_data[7]);
                        System.Media.SystemSounds.Hand.Play();
                    }
           
                    log.attackLog(s);
                }

                var txt = File.ReadAllLines("ports.port");
                var tcp = (from t in txt where t.Contains("tcp") select t).ToArray();   
                if (scan == true)
                {
                    foreach (var item in txt)
                    {
                   
                        if (item.Contains("tcp"))
                        {
                            int inte = Array.IndexOf(txt, item);
                            string cm = txt[inte + 1];

                            string r = item.Replace("tcp", "");
                            int p = Convert.ToInt16(r);

                            if (cm.StartsWith("#"))
                            {

                                scanTCP(e, p, cm);
                         
                               
                            }
                            else
                            {
                                string commend = "您正在使用非加密的明文协议请求使用安全协议";
                                scanTCP(e, p, commend);
                                
                            }
                        }
                    
                        if (item.Contains("udp"))
                        {
                       
                            int inte = Array.IndexOf(txt, item);
                            string cm = txt[inte + 1];

                            string r = item.Replace("udp", "");
                            int p = Convert.ToInt16(r);
                            if (cm.StartsWith("#"))
                            {

                                scanUDP(e, p, cm);
                            
                            }
                            else
                            {
                                string commend = "您正在使用非加密的明文协议请求使用安全协议";
                                scanUDP(e, p, commend);
                            }

                        }
                    }
                }
               
            

        }

        public static void Runcmd()
        {
            Cmd();
            Console.WriteLine("有关特定命令的更多信息，键入- help命令名");
            commend = Console.ReadLine();
            if (commend.Equals("--start arp"))
            {
                Console.WriteLine(" 成功启动Arp欺骗检测工具 ");
                RunArp = true;
            }
            else if (commend == "--start dhcp")
            {
                Console.WriteLine(" 成功启动dhcp欺骗检测工具");
                RunDhcp = true;
            }
            else if (commend == "--start all")
            {
                Console.WriteLine(" 成功启动所有工具");
                RunArp = true;
                RunDhcp = true;
                scan = true;
            }
            else if (commend == "--attacks")
            {
                if (!File.Exists("AttacksDB.txt"))
                {
                    Console.WriteLine("数据库中没有攻击");
               
                    Thread.Sleep(1000);
                    Runcmd();
                }
          
                else
                {
                    var txt = File.ReadAllLines("AttacksDB.txt");
                    foreach (var item in txt)
                    {
                        Console.WriteLine(item);
                    }
                    Console.WriteLine("按回车键返回 ");
                   
                    if (Console.ReadKey().Key == ConsoleKey.Enter)
                    {
                        Thread.Sleep(500);
                        Runcmd();
                    }
               
                }
            }
            else if (commend == "--start scan")
            {
                scan = true;
                Console.WriteLine("Start Scan");
            }
            else if (commend == "-help")
            {
                Runcmd();
            }
            else
            {
                Console.WriteLine(commend + " 不是命令吗,");
                Thread.Sleep(1000);
                Runcmd();
            }
        }
        public static string getGAtWatWayMac(WinPcapDevice dev,string GatewayAddress) 
        {
            RawCapture packet;

      

            while ((packet = dev.GetNextPacket()) != null)
            {

                var mypacket = Packet.ParsePacket(packet.LinkLayerType, packet.Data);
                var arp = (ARPPacket)mypacket.Extract(typeof(ARPPacket));


                if (arp != null)
                {
                  
                    if (arp.Operation == ARPOperation.Response)
                    {
                        if (arp.SenderProtocolAddress.Address == IPAddress.Parse(GatewayAddress).Address)
                        {
                            return arp.SenderHardwareAddress.ToString();
                        }
                    }
                }


            }
            return ""; 

        }
        public static EthernetPacket Protect_Arp(string Router_mac, string My_pc_mac, string Router_ip, string My_pc_ip)
        {
                var eth = new EthernetPacket(PhysicalAddress.Parse(Router_mac), PhysicalAddress.Parse(My_pc_mac), EthernetPacketType.Arp);
                var arp = new ARPPacket(ARPOperation.Request, PhysicalAddress.Parse(My_pc_mac), IPAddress.Parse(My_pc_ip), PhysicalAddress.Parse(Router_mac), IPAddress.Parse(Router_ip));
                eth.PayloadPacket = arp;
                return eth;

        }

        static void scanTCP(CaptureEventArgs e, int port, string cm)
        {
            var _packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcp = (TcpPacket)_packet.Extract(typeof(TcpPacket));
            if (tcp != null)
            {
                if (tcp.DestinationPort == port)
                {
                    var dst_ip = IpPacket.GetEncapsulated(_packet).DestinationAddress.ToString();
                    var src_ip = IpPacket.GetEncapsulated(_packet).SourceAddress.ToString();
                    Console.WriteLine("******************************************************************************");
                    Console.WriteLine(cm+" {0}", port.ToString());
                    Console.WriteLine("Source: {0} " + "Destination: {1}",src_ip,dst_ip);
                   
                }

            }
        }

        static void scanUDP(CaptureEventArgs e, int port, string cm)
        {
            var _packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var udp = (UdpPacket)_packet.Extract(typeof(UdpPacket));
            if (udp != null)
            {
                if (udp.DestinationPort == port)
                {
                    var dst_ip = IpPacket.GetEncapsulated(_packet).DestinationAddress.ToString();
                    var src_ip = IpPacket.GetEncapsulated(_packet).SourceAddress.ToString();
                    Console.WriteLine("********************************************************************");
                    Console.WriteLine(cm + " {0}", port.ToString());
                    Console.WriteLine("Source: {0} " + "Destination: {1}", src_ip, dst_ip);
                    
                }

            }
        }

        static void create_file() 
        {
            using (StreamWriter write = new StreamWriter("ports.port", true))
            {
               
write.WriteLine("80 tcp");
write.WriteLine("#You Are using Clear Text Protocol http Pleas Use secure Protocol Https");
write.WriteLine("21 tcp");
write.WriteLine("#You Are using Clear Text Protocol FTP Pleas Use secure Protocol like SFTP or FTPS");
write.WriteLine("143 tcp");
write.WriteLine("#You Are using Clear Text Protocol IMAP Pleas Use secure Protocol IMAP with ssl");
write.WriteLine("20 tcp");
write.WriteLine("#You Are using Clear Text Protocol FTP Pleas Use secure Protocol like SFTP or FTPS");
write.WriteLine("110 tcp");
write.WriteLine("#You Are using Clear Text Protocol POP3 Pleas Use secure Protocol POP3 with ssl");
write.WriteLine("23 tcp");
write.WriteLine("#You Are using Clear Text Protocol Telnet Pleas Use secure Protocol like SSH");
write.WriteLine("25 tcp");
write.WriteLine("#You Are using Clear Text Protocol SMTP Pleas Use secure Protocol SMTP with ssl");
            }
        }
        public static void Cmd() 
        {

            Console.WriteLine(@"
            Catch  规则

            --start arp    用于检测Arp攻击检测 (Arp spoofing MITM)
            --start dhcp  用于检测Dhcp攻击检测 (Dhcp spoofing MITM )
            --start scan  这是在使用明文协议时通知您
               Like (Http) or (Telent)  

            --Start All   这是开始所有的功能
            --attacks     看到以前所有的攻击记录
             
            ");
            
        }

        public static void cheeck(ado a, string ip, string mac, string Time, int id) 
        {
            Console.WriteLine("你在处理路由器吗 {0}", Environment.MachineName);
            Console.WriteLine("The old Data IP address: {0}, Mac address {1}, Time : {2} , And Interface : {3} , and ID = {4}", ip, mac, Time, Hinter,id);
            
            Console.Write(Environment.NewLine);
            Console.WriteLine("Yas   如果你选择了Yas,Catch会考虑这是你的路由器");
            Console.WriteLine("No    如果你没有选择，Catch会认为这是攻击，所以请小心你选择的 ");
            string ch = Console.ReadLine();
            if (ch == "Yas")
            {
              
                a.Delete(id);
                Console.WriteLine("Delete Old Data {0}", id.ToString());
                
                Data d = new Data() { inter = Hinter, date = DateTime.Now.ToString(), ip = Rip, mac = Rmac, name = "Router" };
                a.insert(d);
            }
            if (ch == "no")
            {
                Console.WriteLine("********************* You Have Been Attacked **************************");
            }
        }


    }
}
