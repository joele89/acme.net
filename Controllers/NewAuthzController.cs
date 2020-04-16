using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace acme.net.Controllers
{
  [Route("newAuthz")]
  [ApiController]
  public class NewAuthzController : ControllerBase
  {
    private readonly AcmeContext _context;
    public NewAuthzController(AcmeContext context)
    {
      _context = context;
    }

    // POST: newAuthz
    [HttpPost]
    public Authorization Post([FromBody] AcmeJWT message)
    {
      //if (message.validate(_context, out Account refAccount))
      if (message.validate(_context))
      {
        string payloadJson = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Decode(message.encodedPayload);
        OrderStub identifier = Newtonsoft.Json.JsonConvert.DeserializeObject<OrderStub>(payloadJson);

        //if not Order OK
        Response.StatusCode = 400;
        //return new AcmeError()
        //{
        //  type = AcmeError.ErrorType.rejectedIdentifier
        //};
        return null;
      }
      else
      {
        Response.StatusCode = 400;
        //return new AcmeError()
        //{
        //  type = AcmeError.ErrorType.malformed
        //};
        return null;
      }
    }
  }
}
