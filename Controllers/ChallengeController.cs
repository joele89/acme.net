using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace acme.net.Controllers
{
  [Route("[controller]")]
  [ApiController]
  public class ChallengeController : ControllerBase
  {
    private readonly AcmeContext _context;
    public ChallengeController(AcmeContext context)
    {
      _context = context;
    }

    [HttpPost("{challengeID}")]
    public Challenge Post(string challengeID, [FromBody] AcmeJWT message)
    {
      if (message.validate(_context, out Account refAccount))
      {
        Challenge reqChallenge = _context.Challenge.Find(challengeID);
        Authorization reqAuth = _context.Authorization.Find(reqChallenge.authID);
        Order reqOrder = _context.Order.Find(reqAuth.orderID);
        if (reqOrder.accountID == refAccount.accountID)
        {
          switch (reqChallenge.type)
          {
            case net.Challenge.ChallengeType.http01:
              {
                reqChallenge.status = net.Challenge.ChallengeStatus.processing;
                reqChallenge.url = baseURL() + "challenge/" + reqChallenge.challengeID;
                try
                {
                  string[] resp = getHTTP01(reqAuth.identifier.value, reqChallenge.token).Split(".");
                  if (resp[0] == reqChallenge.token)
                  {
                    if (message.validateToken(refAccount, resp[1]))
                    {
                      reqChallenge.validated = DateTime.UtcNow;
                      reqChallenge.status = net.Challenge.ChallengeStatus.valid;
                      reqAuth.status = Authorization.AuthorizationStatus.valid;
                    }
                    else
                    {
                      reqChallenge.status = net.Challenge.ChallengeStatus.invalid;
                      reqAuth.status = Authorization.AuthorizationStatus.invalid;
                      Response.Headers.Add("Retry-After", "15");
                      reqChallenge.error = new AcmeError()
                      {
                        type = AcmeError.ErrorType.badSignatureAlgorithm,
                        detail = "Failed to verify signature"
                      };
                    }
                  }
                  else
                  {
                    reqChallenge.status = net.Challenge.ChallengeStatus.invalid;
                    reqAuth.status = Authorization.AuthorizationStatus.invalid;
                    Response.Headers.Add("Retry-After", "15");
                    reqChallenge.error = new AcmeError()
                    {
                      type = AcmeError.ErrorType.incorrectResponse,
                      detail = "Unexpected content in response"
                    };
                  }
                }
                catch (Exception ex)
                {
                  Response.Headers.Add("Retry-After", "15");
                  reqChallenge.status = net.Challenge.ChallengeStatus.invalid;
                  reqAuth.status = Authorization.AuthorizationStatus.invalid;
                  reqChallenge.error = new AcmeError()
                  {
                    type = AcmeError.ErrorType.dns,
                    detail = ex.Message
                  };
                }
                _context.Entry(reqChallenge).State = EntityState.Modified;
                _context.Entry(reqAuth).State = EntityState.Modified;
                _context.SaveChanges();
                break;
              }
            default:
              {
                throw new NotImplementedException();
                break;
              }
          }
          Response.Headers.Add("Link", "<" + baseURL() + "authorization/" + reqAuth.authID + ">;rel=\"up\"");
          Response.Headers.Add("Replay-Nonce", generateNonce());
          return reqChallenge;
        }
        else
        {
          throw new AcmeException() { type = AcmeError.ErrorType.malformed };
        }
      }
      else
      {
        throw new AcmeException() { type = AcmeError.ErrorType.malformed };
      }
    }

    string getHTTP01(string identifier, string token)
    {
      System.Net.WebClient wc = new System.Net.WebClient();
      if (IISAppSettings.HasKey("HTTPProxy"))
      {
        wc.Proxy = new System.Net.WebProxy(IISAppSettings.GetValue("HTTPProxy"));
      }
      return wc.DownloadString("http://" + identifier + "/.well-known/acme-challenge/" + token);
    }
  }
}
