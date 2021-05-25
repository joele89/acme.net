using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace acme.net.Controllers
{
  [Route("[controller]")]
  [ApiController]
  public class FinalizeController : ControllerBase
  {
    private readonly AcmeContext _context;
    public FinalizeController(AcmeContext context)
    {
      _context = context;
    }
    [HttpPost("{acctID}/{orderID}")]
    public ActionResult<Order> Post(string acctID, string orderID, [FromBody] AcmeJWT message)
    {
      if (message.validate(_context, out Account refAccount) && acctID == refAccount.accountID)
      {
        Finalize finalize = Newtonsoft.Json.JsonConvert.DeserializeObject<Finalize>(Base64UrlEncoder.Decode(message.encodedPayload));
        Order order = _context.Order.Find(orderID);
        order.csr = Convert.ToBase64String(Base64UrlEncoder.DecodeBytes(finalize.csr));
        _context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
        _context.SaveChanges();

        order.finalize = baseURL() + "finalize/" + acctID + "/" + orderID;

        List<string> csrNames = new List<string>();

        Response.Headers.Add("Replay-Nonce", generateNonce());

        //get DNS requests from CSR.
        CERTENROLLLib.CX509CertificateRequestPkcs10 certreq;
        try
        {
          certreq = new CERTENROLLLib.CX509CertificateRequestPkcs10();
          certreq.InitializeDecode(order.csr);
          certreq.CheckSignature();
        }
        catch (Exception ex)
        {
          return BadRequest(new AcmeError()
          {
            type = AcmeError.ErrorType.badCSR,
            detail = "Failed to decode CSR, " + ex.Message
          });
        }
        if (IISAppSettings.HasKey("Require-CN-Challenge"))
        {
          try
          {
            string subject = certreq.Subject.Name;
            if (subject.Contains("CN="))
            {
              foreach (string n in subject.Split(","))
              {
                if (n.Trim().StartsWith("CN="))
                {
                  csrNames.Add(n.Trim().Split("=")[1].ToLower());
                }
              }
            }
          }
          catch
          {
            //No Subject specified.
          }
        }

        foreach (CERTENROLLLib.CX509Extension x in certreq.X509Extensions)
        {
          System.Diagnostics.Debug.WriteLine(x.ObjectId.FriendlyName + ":" + x.ObjectId.Value);
          if (x.ObjectId.Value == "2.5.29.17")
          {
            CERTENROLLLib.CX509ExtensionAlternativeNames sans = new CERTENROLLLib.CX509ExtensionAlternativeNames();
            sans.InitializeDecode(CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, x.RawData[CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64]);
            foreach (CERTENROLLLib.CAlternativeName san in sans.AlternativeNames)
            {
              if (san.Type == CERTENROLLLib.AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME)
              {
                csrNames.Add(san.strValue.ToLower());
              }
              else
              {
                return BadRequest(new AcmeError()
                {
                  type = AcmeError.ErrorType.badCSR,
                  detail = "Invalid SANs defined, only DNS SANs are supported"
                });
              }
            }
          }
        }

        order.status = Order.OrderStatus.pending;
        _context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
        _context.SaveChanges();

        Authorization[] authz = _context.Authorization.Where(q => q.orderID == order.orderID).ToArray();

        List<OrderStub> identities = new List<OrderStub>();
        List<String> authList = new List<String>();

        foreach (Authorization orderIdentity in authz)
        {
          identities.Add(new OrderStub() { value = orderIdentity.value, type = orderIdentity.type });
          authList.Add(baseURL() + "authorization/" + orderIdentity.authID);
          csrNames.Remove(orderIdentity.value.ToLower());
        }
        order.identifiers = identities.ToArray();
        order.authorizations = authList.ToArray();
        if (csrNames.Count > 0)
        {
          return BadRequest(
          new AcmeError()
          {
            type = AcmeError.ErrorType.badCSR,
            detail = "CSR contains DNS names not in origional order"
          });
        }
        try
        {
          if (certreq.Template != null)
          {
            return BadRequest(new AcmeError()
            {
              type = AcmeError.ErrorType.badCSR,
              detail = "CSR contains template attribute"
            });
          }
        }
        catch
        {
          //no template attribute
          //ok to proceed
        }

        order.status = Order.OrderStatus.ready;
        _context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
        _context.SaveChanges();

        Response.Headers.Add("Retry-After", "15");
        AcmeError e = CAInterface.submitCSR(_context, order);
        if (e != null)
        {
          Response.StatusCode = 500;
          return new ObjectResult(e);
        }

        return order;
      }
      else
      {
        return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
      }
    }
  }
}
