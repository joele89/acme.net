using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Policy;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.IdentityModel.Tokens;

namespace acme.net.Controllers
{
  [Route("[controller]")]
  [ApiController]
  public class revokeCertController : ControllerBase
  {
    private readonly AcmeContext _context;
    public revokeCertController(AcmeContext context)
    {
      _context = context;
    }
    // POST: newOrder
    [HttpPost]
    public ActionResult Post([FromBody] AcmeJWT message)
    {
      try
      {
        if (message.validate(_context, out Account refAccount))
        {
          string payloadJson = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Decode(message.encodedPayload);
          Revocation reqRevocation = Newtonsoft.Json.JsonConvert.DeserializeObject<Revocation>(payloadJson);
          Order order = _context.Order.Where(q => q.certificate == reqRevocation.certificate).FirstOrDefault();
          reqRevocation.reason ??= Revocation.Reason.unspecified;
          if (refAccount != null)
          {
            if (order.accountID == refAccount.accountID)
            { //Account requested certificate
              order.revocationReason = reqRevocation.reason;
              _context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
              _context.SaveChanges();
              return Ok();
            }
            else
            {
              //Account controls identifiers
              List<string> orderIdentifiers = _context.Authorization.Where(q => q.orderID == order.orderID).Select(q => q.value).ToList();
              List<string> authorizedIdentifiers = _context.Order.Where(q => q.accountID == refAccount.accountID).Join(_context.Authorization, o => o.orderID, i => i.orderID, (o, a) => a).Where(q => orderIdentifiers.Contains(q.value) && q.status == Authorization.AuthorizationStatus.valid).Select(q => q.value).ToList();
              List<string> unauthorisedIdentifiers = orderIdentifiers.Where(q => !authorizedIdentifiers.Contains(q)).ToList();

              if (unauthorisedIdentifiers.Count == 0)
              {
                order.revocationReason = reqRevocation.reason;
                _context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
                _context.SaveChanges();
                return Ok();
              }
              else
              {
                return Forbidden(new AcmeError() { type = AcmeError.ErrorType.unauthorized, detail = "No authorization provided" });
              }
            }
          }
          else
          {
            //Requester controls private key (message validated, but has no account reference)
            string decodedHeader = Base64UrlEncoder.Decode(message.encodedJWTHeader);
            JWTHeader header = Newtonsoft.Json.JsonConvert.DeserializeObject<JWTHeader>(decodedHeader);
            X509Certificate certificate = new X509Certificate(System.Text.Encoding.ASCII.GetBytes(reqRevocation.certificate));
            bool keyMatch = header.jwk.kty switch
            {
              "RSA" => Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(header.jwk.n).SequenceEqual(certificate.GetPublicKey()),
              "EC" => throw new NotImplementedException(),
              _ => false,
            };
            if (keyMatch)
            {
              order.revocationReason = reqRevocation.reason;
              _context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
              _context.SaveChanges();
              return Ok();
            }
            else
            {
              return Forbidden(new AcmeError() { type = AcmeError.ErrorType.unauthorized, detail = "No authorization provided" });
            }
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
