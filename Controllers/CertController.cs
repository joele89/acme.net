using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace acme.net.Controllers
{
  [Route("[controller]")]
  [ApiController]
  public class CertController : ControllerBase
  {
    private readonly AcmeContext _context;
    public CertController(AcmeContext context)
    {
      _context = context;
    }
    [HttpPost("{acctID}/{orderID}")]
    public string Post(string acctID, string orderID, [FromBody] AcmeJWT message)
    {
      if (message.validate(_context, out Account refAccount) && acctID == refAccount.accountID)
      {
        Order order = _context.Order.Find(orderID);
        Response.Headers.Add("Replay-Nonce", generateNonce());

        if (order.certificate == null)
        {
          Response.Headers.Add("Retry-After", "15");
          return null;
        }
        else
        {
          //Response.Headers.Add("Content-Type", "application/x-x509-ca-cert");
          string ret = "";
          ret += order.certificate;
          if (IISAppSettings.HasKey("CAChain"))
          {
            System.IO.StreamReader reader = new System.IO.StreamReader(IISAppSettings.GetValue("CAChain"));
            ret += reader.ReadToEnd();
          }
          return ret;
        }
      }
      else
      {
        throw new AcmeException() { type = AcmeError.ErrorType.malformed };
      }
    }
  }
}
