using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace acme.net.Controllers
{
  [Route("[controller]")]
  [Route("")]
  [ApiController]
  public class directoryController : ControllerBase
  {
    // GET: directory
    [HttpGet]
    public Directory Get()
    {

      Directory d = new Directory
      {
        newNonce = baseURL() + "newNonce",
        newAccount = baseURL() + "newAccount",
        newOrder = baseURL() + "newOrder",
        revokeCert = baseURL() + "revokeCert",
        keyChange = baseURL() + "keyChange"
      };
      if (IISAppSettings.HasKey("newAuthz"))
      {
        d.newAuthz = IISAppSettings.GetValue("newAuthz");
      }
      return d;
    }
  }
}
