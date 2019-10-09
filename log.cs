using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Ng_IDS.Model;

namespace Open_HIDS
{
    class log
    {
        public static void writeError(Exception ex) 
        {
            StreamWriter wr = null;
            try
            {
                wr = new StreamWriter(AppDomain.CurrentDomain.BaseDirectory+"Log.txt",true);
                wr.WriteLine(DateTime.Now.ToString()+": "+ex.Source.ToString().Trim() +" ; "+ex.Message.ToString().Trim());
                wr.Flush();
                wr.Close();
            }
            catch (Exception)
            {
                
                throw;
            }
        }

        public static void Evint(string action) 
        {
            StreamWriter wr = null;
            try
            {
                wr = new StreamWriter(AppDomain.CurrentDomain.BaseDirectory + "Log.txt", true);
                wr.WriteLine(DateTime.Now.ToString() +": "+action);
                wr.Flush();
                wr.Close();
            }
            catch (Exception)
            {

                throw;
            }
        }

        public static void attackLog(scan s)
        {
            StreamWriter wr = null;
            try
            {
                wr = new StreamWriter(AppDomain.CurrentDomain.BaseDirectory + "AttacksDB.txt", true);
                wr.WriteLine(DateTime.Now.ToString() + ": " + "Attacke Name : {0} , Time : {1} , Attacker HardwareAddress : {2} , Attacker ip address : {3} ", s.Attack_data[0], s.Attack_data[3], s.Attack_data[2], s.Attack_data[1]);
                wr.Flush();
                wr.Close();
            }
            catch (Exception)
            {

                throw;
            }
        }
    }
}
