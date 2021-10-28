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
    public ActionResult<byte[]> Post(string acctID, string orderID, [FromBody] AcmeJWT message)
    {
      try
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
            string ret = "";
            ret += order.certificate;
            CERTENROLLLib.CX509CertificateRequestPkcs10 certreq = new CERTENROLLLib.CX509CertificateRequestPkcs10();
            certreq.InitializeDecode(order.csr);
            string csrAlgo = certreq.PublicKey.Algorithm.FriendlyName;
            if (IISAppSettings.HasKey(csrAlgo + "-CAChain"))
            {
              System.IO.StreamReader reader = new System.IO.StreamReader(IISAppSettings.GetValue(csrAlgo + "-CAChain"));
              ret += reader.ReadToEnd();
            }
            return File(System.Text.Encoding.ASCII.GetBytes(ret), "application/pem-certificate-chain");
          }
        }
        else
        {
          return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
        }
      }
      catch (AcmeException ex)
      {
        return BadRequest(new AcmeError() { type = ex.type, detail = ex.detail, instance = ex.instance, reference = ex.reference, subproblems = ex.subproblems });
      }
    }
  }
}
