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
  public class newNonceController : ControllerBase
  {
    // GET: newNonce
    [HttpGet]
    public void Get()
    {
      Response.StatusCode = 204;
      Response.Headers.Add("Replay-Nonce", generateNonce());
    }

    // HEAD: newNonce
    [HttpHead]
    public void Head()
    {
      Response.Headers.Add("Replay-Nonce", generateNonce());
    }
  }
}
