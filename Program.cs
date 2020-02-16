using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
//using System.Security.Cryptography;

namespace acme.net
{
  public class Program
  {
    public static void Main(string[] args)
    {
      CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
              webBuilder.UseStartup<Startup>();
            });
  }

  public class IISAppSettings
  {
    static public string GetValue(string key)
    {
      System.IO.FileStream xmlStream = new System.IO.FileStream("web.config", System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite);
      System.Xml.XmlReader xml = System.Xml.XmlReader.Create(xmlStream);
      xml.MoveToContent();
      bool inAppSettings = false;
      while (xml.Read())
      {
        switch (xml.NodeType)
        {
          case System.Xml.XmlNodeType.Element:
            if (xml.Name == "appSettings") inAppSettings = true;
            if (xml.Name == "add" && inAppSettings && xml.GetAttribute("key") == key) return xml.GetAttribute("value");
            break;
          case System.Xml.XmlNodeType.EndElement:
            if (xml.Name == "appSettings") inAppSettings = false;
            break;
        }
      }
      throw new KeyNotFoundException();
    }
    static public bool HasKey(string key)
    {
      System.IO.FileStream xmlStream = new System.IO.FileStream("web.config", System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite);
      System.Xml.XmlReader xml = System.Xml.XmlReader.Create(xmlStream);
      xml.MoveToContent();
      bool inAppSettings = false;
      while (xml.Read())
      {
        switch (xml.NodeType)
        {
          case System.Xml.XmlNodeType.Element:
            if (xml.Name == "appSettings") inAppSettings = true;
            if (xml.Name == "add" && inAppSettings && xml.GetAttribute("key") == key) return true;
            break;
          case System.Xml.XmlNodeType.EndElement:
            if (xml.Name == "appSettings") inAppSettings = false;
            break;
        }
      }
      return false;
    }
  }
}
