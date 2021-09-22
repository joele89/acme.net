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
  public class AuthorizationController : ControllerBase
  {
    private readonly AcmeContext _context;
    public AuthorizationController(AcmeContext context)
    {
      _context = context;
    }

    [HttpPost("{id}")]
    public ActionResult<Authorization> Post(string id, [FromBody] AcmeJWT message)
    {
      try
      {
        if (message.validate(_context, out Account refAccount))
        {
          Authorization retAuth = _context.Authorization.Find(id);
          Order order = _context.Order.Find(retAuth.orderID);
          if (order.accountID == refAccount.accountID)
          {
            List<Challenge> challenges = new List<Challenge>();
            if (!IISAppSettings.HasKey("Disable-HTTP-Challenge"))
            {
              Challenge httpChallenge = _context.Challenge.Where(q => q.authID == retAuth.authID && q.type == net.Challenge.ChallengeType.http01).FirstOrDefault();
              if (httpChallenge == null)
              {
                httpChallenge = new Challenge()
                {
                  authID = retAuth.authID,
                  challengeID = generateID(),
                  type = acme.net.Challenge.ChallengeType.http01,
                  token = generateToken(),
                };
                _context.Challenge.Add(httpChallenge);
              }
              httpChallenge.url = baseURL() + "challenge/" + httpChallenge.challengeID;
              challenges.Add(httpChallenge);
            }
            if (!IISAppSettings.HasKey("Disable-DNS-Challenge"))
            {
              Challenge dnsChallenge = _context.Challenge.Where(q => q.authID == retAuth.authID && q.type == net.Challenge.ChallengeType.dns01).FirstOrDefault();
              if (dnsChallenge == null)
              {
                dnsChallenge = new Challenge()
                {
                  authID = retAuth.authID,
                  challengeID = generateID(),
                  type = acme.net.Challenge.ChallengeType.dns01,
                  token = generateToken()
                };
                _context.Challenge.Add(dnsChallenge);
              }
              dnsChallenge.url = baseURL() + "challenge/" + dnsChallenge.challengeID;
              challenges.Add(dnsChallenge);
            }
            if (!IISAppSettings.HasKey("Disable-TLSALPN-Challenge"))
            {
              throw new NotImplementedException();
              Challenge tlsChallenge = _context.Challenge.Where(q => q.authID == retAuth.authID && q.type == net.Challenge.ChallengeType.tlsalpn01).FirstOrDefault();
              if (tlsChallenge == null)
              {
                tlsChallenge = new Challenge()
                {
                  authID = retAuth.authID,
                  challengeID = generateID(),
                  type = acme.net.Challenge.ChallengeType.tlsalpn01,
                  token = generateToken()
                };
                _context.Challenge.Add(tlsChallenge);
              }
              tlsChallenge.url = baseURL() + "challenge/" + tlsChallenge.challengeID;
              challenges.Add(tlsChallenge);
            }
            if (challenges.Count > 0)
            {
              _context.SaveChanges();
              retAuth.challenges = challenges.ToArray();
              Response.Headers.Add("Retry-After", "15");
              Response.Headers.Add("Replay-Nonce", generateNonce());
              return retAuth;
            }
            else
            {
              throw new AcmeException() { type = AcmeError.ErrorType.serverInternal, detail = "All Challenge types disabled" };
            }
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
  }
}
