using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data;
using System.Data.SQLite;
using System.IO;

namespace Ng_IDS.Model
{
    class ado
    {
        public SQLiteConnection conn = new SQLiteConnection("Data Source=data.sqlite;Version=3;");

        public void creatDB() 
        {
                 try
                {
                SQLiteConnection.CreateFile("data.sqlite");
                SQLiteConnection my;
                my = new SQLiteConnection("Data Source=data.sqlite;Version=3;");
                my.Open();                                              
                string sql = "Create Table mac(id integer Primary key AUTOINCREMENT,name varchar(500),inter varchar(500),mac_ad varchar(500),ip varchar(500),date varchar(500))";
                SQLiteCommand comm = new SQLiteCommand(sql, my);
                comm.ExecuteNonQuery();
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }
            
        }
        public void insert(Data dt)
        {
            if (conn.State == ConnectionState.Closed)
            {
                conn.Open();
            }
            var sql = "Insert into mac(name,inter,mac_ad,ip,date) values (@name,@inter,@mac_ad,@ip,@date)";
            SQLiteCommand cmd = new SQLiteCommand(sql, conn);
       
            cmd.Parameters.AddWithValue("@name", dt.name);
            cmd.Parameters.AddWithValue("@inter", dt.inter);
            cmd.Parameters.AddWithValue("@mac_ad", dt.mac);
            cmd.Parameters.AddWithValue("@ip", dt.ip);
            cmd.Parameters.AddWithValue("@date", dt.date);
            cmd.ExecuteNonQuery();
            conn.Close();
        }

        public DataTable selectname(string name,string Interface)
        {
            if (conn.State == ConnectionState.Closed)
            {
                conn.Open(); 
            }
            
            var sql =string.Format("Select * from mac where name='{0}' and inter='{1}'", name, Interface);
            SQLiteCommand cmd = new SQLiteCommand(sql, conn);
            //cmd.ExecuteReader();
            DataTable tp = new DataTable();
            SQLiteDataAdapter adp = new SQLiteDataAdapter(cmd);
            adp.Fill(tp);
            return tp;
            conn.Close();
        }

        public DataTable selectAll()
        {
            conn.Open();
            var sql = "Select * from mac";
            SQLiteCommand cmd = new SQLiteCommand(sql, conn);
            DataTable tp = new DataTable();
            SQLiteDataAdapter adp = new SQLiteDataAdapter(cmd);
            adp.Fill(tp);
            return tp;
            conn.Close();
        }

        public void Delete(int id)
        {
            using (SQLiteConnection con = new SQLiteConnection("Data Source=data.sqlite;Version=3;"))
            {
                con.Open();
                var sql = "DELETE FROM mac where id=@id";
                SQLiteCommand cmd = new SQLiteCommand(sql, con);
                cmd.Parameters.AddWithValue("@id", id);
                cmd.ExecuteNonQuery();
                conn.Close();
            }
           ;

        }

        public DataTable select(Data dt)
        {
            conn.Open();
            var sql = string.Format("Select * from mac where inter='{0}'", dt.inter);
            SQLiteCommand cmd = new SQLiteCommand(sql, conn);
            //cmd.ExecuteReader();
            DataTable tp = new DataTable();
            SQLiteDataAdapter adp = new SQLiteDataAdapter(cmd);
            adp.Fill(tp);
            return tp;
            // conn.Close();
        }

        public DataTable selectmac(string mac,string inter)
        {
            conn.Open();
            var sql = string.Format("Select * from mac where mac_ad='{0}' and name ='Router' and inter='{1}'", mac,inter);
            SQLiteCommand cmd = new SQLiteCommand(sql, conn);
            //cmd.ExecuteReader();
            DataTable tp = new DataTable();
            SQLiteDataAdapter adp = new SQLiteDataAdapter(cmd);
            adp.Fill(tp);
            return tp;
            // conn.Close();
        }

        public DataTable checkpc(string ip,string mac, string inter)
        {
            conn.Open();
            var sql = string.Format("Select * from mac where mac_ad='{0}' and name ='PC' and inter='{1}' and ip ='{2}'", mac, inter,ip);
            SQLiteCommand cmd = new SQLiteCommand(sql, conn);
            //cmd.ExecuteReader();
            DataTable tp = new DataTable();
            SQLiteDataAdapter adp = new SQLiteDataAdapter(cmd);
            adp.Fill(tp);
            return tp;
            // conn.Close();
        }
        public string selectmacstring(string inter)
        {
            conn.Open();
            var sql = string.Format("Select * from mac where  name='Router' and inter='{0}'", inter);
            SQLiteCommand cmd = new SQLiteCommand(sql, conn);
            //cmd.ExecuteReader();
            DataTable tp = new DataTable();
            SQLiteDataAdapter adp = new SQLiteDataAdapter(cmd);
            adp.Fill(tp);
            if (tp.Rows.Count > 0)
            {
                foreach (DataRow item in tp.Rows)
                {
                    return item["mac_ad"].ToString();
                }
            }
            return "";

            // conn.Close();
        }

        public int selectId(string inter)
        {
            conn.Open();
            var sql = "Select * from mac where inter=@in and name='Router'";
            SQLiteCommand cmd = new SQLiteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@in", inter);
            //cmd.ExecuteReader();
            DataTable tp = new DataTable();
            SQLiteDataAdapter adp = new SQLiteDataAdapter(cmd);
            adp.Fill(tp);
            if (tp.Rows.Count > 0)
            {
                foreach (DataRow item in tp.Rows)
                {
                    int f =Convert.ToInt16(item[0]); 
                    return f;
                }
            }
            return 0;
            //conn.Close();
            // conn.Close();
        }
        public void up(int id,string ip,string mac)
        {
            SQLiteConnection con = new SQLiteConnection("Data Source=data.sqlite;Version=3;");
            con.Open();
            string sql = string.Format("Update mac SET mac_ad=@mac and ip=@ip and date=@d where id=@id");
           // SQLiteCommand cmd = new SQLiteCommand("Update tp Set name = @n Where id= '1'", conn);
            SQLiteCommand cmd = new SQLiteCommand(sql, con);
            cmd.Parameters.AddWithValue("@ip", "ffdfdf");
            cmd.Parameters.AddWithValue("@mac", "Gdsdgzsdf");
            cmd.Parameters.AddWithValue("@id", id);
            cmd.Parameters.AddWithValue("@d", DateTime.Now.ToString());
            cmd.ExecuteNonQuery();
            conn.Close();
        }
    }

    // most id be unic
    //
}
