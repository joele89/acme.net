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
  public class keyChangeController : ControllerBase
  {
    private readonly AcmeContext _context;
    public keyChangeController(AcmeContext context)
    {
      _context = context;
    }
    [HttpPost]
    public ActionResult<string> Post([FromBody] AcmeJWT outer)
    {
      //1. Validate the POST request belongs to a currently active account, as described in Section 6.
      if (outer.validate(_context, out Account referenceAccount))
      {
        if (referenceAccount == null)
        {
          return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
        }
        if (referenceAccount.status != Account.AccountStatus.valid)
        {
          return Unauthorized(new AcmeError() { type = AcmeError.ErrorType.unauthorized });
        }
        //2. Check that the payload of the JWS is a well-formed JWS object (the "inner JWS").
        AcmeJWT inner = Newtonsoft.Json.JsonConvert.DeserializeObject<AcmeJWT>(outer.encodedPayload);
        JWTHeader innerHeader = Newtonsoft.Json.JsonConvert.DeserializeObject<JWTHeader>(inner.encodedJWTHeader);
        //3. Check that the JWS protected header of the inner JWS has a "jwk" field.
        if (innerHeader.jwk == null)
        {
          return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
        }
        //4. Check that the inner JWS verifies using the key in its "jwk" field.
        if (!inner.validate(_context))
        {
          return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
        }
        KeyChange keyChange;
        try
        {
          //5. Check that the payload of the inner JWS is a well-formed keyChange object(as described above).
          keyChange = Newtonsoft.Json.JsonConvert.DeserializeObject<KeyChange>(inner.encodedPayload);
        }
        catch
        {
          return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
        }
        //6. Check that the "url" parameters of the inner and outer JWSs are the same.
        JWTHeader outerHeader = Newtonsoft.Json.JsonConvert.DeserializeObject<JWTHeader>(outer.encodedJWTHeader);
        if (outerHeader.url != innerHeader.url)
        {
          return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
        }

        //7. Check that the "account" field of the keyChange object contains the URL for the account matching the old key(i.e., the "kid" field in the outer JWS).
        Account.Key acctKey = _context.AccountKey.Find(referenceAccount.accountID);
        if (keyChange.account != outerHeader.kid)
        {
          return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
        }
        //8. Check that the "oldKey" field of the keyChange object is the same  as the account key for the account in question.
        if (acctKey.n != keyChange.oldkey)
        {
          return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
        }
        //9. Check that no account exists whose account key is the same as the key in the "jwk" header parameter of the inner JWS.
        if (_context.AccountKey.Where(q => q.n == innerHeader.jwk.n).Count() > 0)
        {
          string existingID = _context.AccountKey.Where(q => q.n == innerHeader.jwk.n).Select(q => q.accountID).ToString();
          Response.Headers.Add("Location", baseURL() + "/" + existingID);
          return Conflict(new AcmeError() { type = AcmeError.ErrorType.badPublicKey });
        }

        acctKey.n = innerHeader.jwk.n;
        //_context.AccountKey.Update(acctKey);
        _context.Entry(acctKey).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
        _context.SaveChanges();

        return null;
      }
      else
      {
        return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
      }
    }
  }
}
