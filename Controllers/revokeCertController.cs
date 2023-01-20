using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Policy;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
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
          string payloadJson = Base64UrlEncoder.Decode(message.encodedPayload);
          Revocation reqRevocation = Newtonsoft.Json.JsonConvert.DeserializeObject<Revocation>(payloadJson);
          string b64Cert = Convert.ToBase64String(Base64UrlEncoder.DecodeBytes(reqRevocation.certificate));
          Order order = _context.Order.Where(q => Convert.ToString(q.certificate).Replace("\n", "").Replace("\r", "").Contains(b64Cert)).FirstOrDefault();
          if (order == null)
            return NotFound(new AcmeError() { type = AcmeError.ErrorType.incorrectResponse, detail = "Provided certificate not found" });
          if (order.revocationReason != null)
            return BadRequest(new AcmeError() { type = AcmeError.ErrorType.alreadyRevoked, detail = "Provided certificate has already been revoked" });
          reqRevocation.reason ??= Revocation.Reason.unspecified;
          if (refAccount != null)
          {
            if (order.accountID == refAccount.accountID)
            { //Account requested certificate
              CAInterface.revokeCertificate(order, (int)reqRevocation.reason.Value);
              order.revocationReason = reqRevocation.reason;
              _context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
              _context.SaveChanges();
              Response.Headers.Add("Replay-Nonce", generateNonce());
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
                CAInterface.revokeCertificate(order, (int)reqRevocation.reason.Value);
                order.revocationReason = reqRevocation.reason;
                _context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
                _context.SaveChanges();
                Response.Headers.Add("Replay-Nonce", generateNonce());
                return Ok();
              }
              else
              {
                return Forbidden(new AcmeError() { type = AcmeError.ErrorType.unauthorized, detail = "Account hasn't demonstrated appropriate control" });
              }
            }
          }
          else
          {
            //Requester controls private key (message validated, but has no account reference)
            string decodedHeader = Base64UrlEncoder.Decode(message.encodedJWTHeader);
            JWTHeader header = Newtonsoft.Json.JsonConvert.DeserializeObject<JWTHeader>(decodedHeader);
            X509Certificate certificate = new X509Certificate(Base64UrlEncoder.DecodeBytes(reqRevocation.certificate));
            bool keyMatch = false;
            switch (header.jwk.kty)
            {
              case "RSA":
                AsnReader asn = new AsnReader(certificate.GetPublicKey(), AsnEncodingRules.DER);
                System.Numerics.BigInteger keyInt = asn.ReadSequence().ReadInteger();
                byte[] keyBytes = keyInt.ToByteArray();
                Array.Reverse(keyBytes);
                keyBytes = keyBytes[1..];
                keyMatch = Base64UrlEncoder.DecodeBytes(header.jwk.n).SequenceEqual(keyBytes);
                break;
              case "EC": throw new NotImplementedException(); break;
            }
            if (keyMatch)
            {
              CAInterface.revokeCertificate(order, (int)reqRevocation.reason.Value);
              order.revocationReason = reqRevocation.reason;
              _context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
              _context.SaveChanges();
              Response.Headers.Add("Replay-Nonce", generateNonce());
              return Ok();
            }
            else
            {
              return Forbidden(new AcmeError() { type = AcmeError.ErrorType.unauthorized, detail = "Provided certificate does not demonstrate appropriate control" });
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
