using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace acme.net.Controllers
{
  [Route("[controller]")]
  [ApiController]
  public class newAccountController : ControllerBase
  {
    private readonly AcmeContext _context;
    public newAccountController(AcmeContext context)
    {
      _context = context;
    }

    // POST: newAccount
    [HttpPost]
    public ActionResult<Account> Post([FromBody] AcmeJWT message)
    {
      if (message.validate(_context))
      {
        string protectedJson = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Decode(message.encodedJWTHeader);
        JWTHeader jWTHeader = Newtonsoft.Json.JsonConvert.DeserializeObject<JWTHeader>(protectedJson);
        string payloadJson = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Decode(message.encodedPayload);
        AccountStub stub = Newtonsoft.Json.JsonConvert.DeserializeObject<AccountStub>(payloadJson);

        Account.Key searchKey = null;
        try
        {
          switch (jWTHeader.alg)
          {
            case "RS256":
              searchKey = _context.AccountKey.Where(key => key.n == jWTHeader.jwk.n).FirstOrDefault();
              break;
            case "ES256":
            case "ES384":
            case "ES521":
              searchKey = _context.AccountKey.Where(key => key.x == jWTHeader.jwk.x && key.y == jWTHeader.jwk.y).FirstOrDefault();
              break;
            default:
              return BadRequest(new AcmeError() { type = AcmeError.ErrorType.badPublicKey });
          }
        }
        catch { }

        if (searchKey == null)
        {
          if (stub.onlyReturnExisting == null || stub.onlyReturnExisting == false)
          {
            //No existing account found, creating
            Account account = new Account(_context)
            {
              accountID = generateID(),
              status = Account.AccountStatus.valid,
              termsOfServiceAgreed = (stub.termsOfServiceAgreed == true)
            };
            _context.Account.Add(account);

            Account.Key newKey = Account.Key.FromJWK(jWTHeader.jwk);
            newKey.accountID = account.accountID;
            _context.AccountKey.Add(newKey);
            if (stub.contact != null)
            {
              foreach (String contactString in stub.contact)
              {
                if (Regex.Match(contactString, "mailto:\\s*.*", RegexOptions.IgnoreCase).Success)
                {
                  Contact newContact = new Contact()
                  {
                    accountID = account.accountID,
                    contact = contactString
                  };
                  _context.Contact.Add(newContact);
                } else
                {
                  return BadRequest(new AcmeError() { type = AcmeError.ErrorType.invalidContact, detail = "Bad contact address format" });
                }
              }
            }
            else if (IISAppSettings.HasKey("Contact-Required") && IISAppSettings.GetValue("Contact-Required") == "True")
            {
              return BadRequest(new AcmeError() { type = AcmeError.ErrorType.invalidContact, detail = "A contact email address is required by this CA" });
            }
            _context.SaveChanges();

            Response.Headers.Add("Replay-Nonce", generateNonce());
            Response.Headers.Add("Location", baseURL() + "account/" + account.accountID);
            Response.StatusCode = 201;
            //CreatedAtAction("GetAccount", new { id = account.accountID }, account);
            Account ret = new Account(_context)
            {
              accountID = account.accountID,
              status = Account.AccountStatus.valid,
              termsOfServiceAgreed = (stub.termsOfServiceAgreed == true)
            };
            ret.baseUrl = baseURL();
            return ret;
          }
          else
          {
            //Only Return Existing, No existing
            Response.Headers.Add("Replay-Nonce", generateNonce());
            return NotFound(new AcmeError() { type = AcmeError.ErrorType.accountDoesNotExist });
          }
        }
        else
        {
          //Return existing (Found) account
          Account ret = _context.Account.Find(searchKey.accountID);
          ret.key = searchKey;
          Response.Headers.Add("Replay-Nonce", generateNonce());
          Response.Headers.Add("Location", baseURL() + "account/" + ret.accountID);
          Response.StatusCode = 200;
          ret.baseUrl = baseURL();
          return ret;
        }
      }
      else
      {
        //Message validation failed
        Response.Headers.Add("Replay-Nonce", generateNonce());
        return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
      }
    }
    private bool AccountExists(string id)
    {
      return _context.Account.Any(e => e.accountID == id);
    }
  }
}
