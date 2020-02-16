using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace acme.net.Controllers
{
  public class ControllerBase : Microsoft.AspNetCore.Mvc.ControllerBase
  { 
    public string baseURL()
    {
      return baseURL(Request);
    }
    /*
    static public string base64decode(string base64, bool assumePadding = false)
    {
      if (assumePadding)
      {
        base64 = base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
      }
      return System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(base64));
    }
    */
    static public string baseURL(Microsoft.AspNetCore.Http.HttpRequest request)
    {
      //read from web.config file first...
      if (IISAppSettings.HasKey("baseURL"))
      {
        return IISAppSettings.GetValue("baseURL") + "/";
      }
      else
      {
        //if web.config doesn't have the setting, determine automatically from binding info.
        return request.Scheme + "://" + request.Host.Value + request.PathBase + "/";
      }
    }
    static public string generateToken()
    {
      return generateRandomString(44);
    }
    static public string generateNonce()
    {
      return generateRandomString(22);
    }
    static public string generateID()
    {
      return generateRandomString(12);
    }
    static string generateRandomString(int length)
    {
      string ret = "";
      for (int count1 = 1; count1 <= length; count1++)
      {
        Random r = new Random();

        int rn = r.Next(1, 62);
        if (rn < 10) ret += rn.ToString(); //Digit
        if (10 <= rn && rn < 36) ret += (char)(rn - 10 + 0x41); //Uppercase
        if (36 <= rn) ret += (char)(rn - 36 + 0x61); //Lowercase
      }
      return ret;
    }
  }
}
