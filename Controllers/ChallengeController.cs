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
    public ActionResult<Challenge> Post(string challengeID, [FromBody] AcmeJWT message)
    {
      try
      {
        if (message.validate(_context, out Account refAccount))
        {
          Challenge reqChallenge = _context.Challenge.Find(challengeID);
          Authorization reqAuth = _context.Authorization.Find(reqChallenge.authID);
          Order reqOrder = _context.Order.Find(reqAuth.orderID);
          if (reqOrder.accountID == refAccount.accountID)
          {
            reqChallenge.status = net.Challenge.ChallengeStatus.processing;
            reqChallenge.url = baseURL() + "challenge/" + reqChallenge.challengeID;
            try
            {
              bool challengeResult = false;
              string accountHash = AcmeJWT.calculateAccountHash(refAccount);
              switch (reqChallenge.type)
              {
                case net.Challenge.ChallengeType.http01:
                  {
                    challengeResult = getHTTP01(reqAuth.identifier.value, reqChallenge.token, accountHash);
                    break;
                  }
                case net.Challenge.ChallengeType.dns01:
                  {
                    string tokenHash = AcmeJWT.calculateTokenHash(reqChallenge.token + "." + accountHash, refAccount.key.GetHashName());
                    challengeResult = getDNS01(reqAuth.identifier.value, tokenHash);
                    break;
                  }
                default:
                  {
                    throw new NotImplementedException();
                    break;
                  }
              }
              if (challengeResult)
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
                  type = AcmeError.ErrorType.incorrectResponse,
                  detail = "Retrieved token doesn't match expected value"
                };
              }

            }
            catch (NotImplementedException ex)
            {
              throw ex;
            }
            catch (AcmeException ex)
            {
              reqChallenge.status = net.Challenge.ChallengeStatus.invalid;
              reqAuth.status = Authorization.AuthorizationStatus.invalid;
              Response.Headers.Add("Retry-After", "15");
              reqChallenge.error = new AcmeError()
              {
                type = ex.type,
                detail = ex.detail,
              };
            }
            catch (Exception ex)
            {
              reqChallenge.status = net.Challenge.ChallengeStatus.invalid;
              reqAuth.status = Authorization.AuthorizationStatus.invalid;
              Response.Headers.Add("Retry-After", "15");
              reqChallenge.error = new AcmeError()
              {
                type = AcmeError.ErrorType.serverInternal,
                detail = "Internal server error occured while retriving token",
                subproblems = new AcmeError[] { new AcmeError()
                  {
                    type = AcmeError.ErrorType.serverInternal,
                    detail = ex.Message
                  },
                  new AcmeError()
                  {
                    type = AcmeError.ErrorType.serverInternal,
                    detail = ex.StackTrace
                  }
                }
              };
            }

            _context.Entry(reqChallenge).State = EntityState.Modified;
            _context.Entry(reqAuth).State = EntityState.Modified;
            _context.SaveChanges();

            Response.Headers.Add("Link", "<" + baseURL() + "authorization/" + reqAuth.authID + ">;rel=\"up\"");
            Response.Headers.Add("Replay-Nonce", generateNonce());
            return reqChallenge;
          }
          else
          {
            return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
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

    bool getHTTP01(string identifier, string challengeToken, string accountHash)
    {
      System.Net.WebClient wc = new System.Net.WebClient();
      if (IISAppSettings.HasKey("HTTPProxy"))
      {
        wc.Proxy = new System.Net.WebProxy(IISAppSettings.GetValue("HTTPProxy"));
      }
      try
      {
        string ret = wc.DownloadString("http://" + identifier + "/.well-known/acme-challenge/" + challengeToken);
        return (ret.Trim() == challengeToken + "." + accountHash);
      } catch (System.Net.WebException ex)
      {
        throw new AcmeException()
        {
          type = AcmeError.ErrorType.connection,
          detail = ex.Message
        };
      }
    }

    bool getDNS01(string identifier, string dnsToken)
    {
      DnsClient.LookupClient lc = new DnsClient.LookupClient();
#warning TODO: identify/connect to authoritave name server
#warning TODO: Wildcard Support
      DnsClient.IDnsQueryResponse qr = lc.Query("_acme-challenge." + identifier, DnsClient.QueryType.TXT);
      if (qr.Answers.Count > 0)
      {
        foreach (DnsClient.Protocol.TxtRecord record in qr.Answers)
        {
          if (record.Text.First() == dnsToken) { return true; }
        }
      }
      else
      {
        throw new AcmeException()
        {
          type = AcmeError.ErrorType.connection,
          detail = "Couldn't retrieve DNS record"
        };
      }
      return false;
    }
  }
}
