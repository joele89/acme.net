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
    public Authorization Post(string id, [FromBody] AcmeJWT message)
    {
      if (message.validate(_context, out Account refAccount))
      {
        Authorization retAuth = _context.Authorization.Find(id);
        Order order = _context.Order.Find(retAuth.orderID);
        if (order.accountID == refAccount.accountID)
        {
          List<Challenge> challenges = new List<Challenge>();
          if (!IISAppSettings.HasKey("Disable-HTTP-Chalenge"))
          {
            Challenge httpChalenge = _context.Challenge.Where(q => q.authID == retAuth.authID && q.type == net.Challenge.ChallengeType.http01).FirstOrDefault();
            if (httpChalenge == null)
            {
              httpChalenge = new Challenge()
              {
                authID = retAuth.authID,
                challengeID = generateID(),
                type = acme.net.Challenge.ChallengeType.http01,
                token = generateToken(),
              };
              _context.Challenge.Add(httpChalenge);
            }
            httpChalenge.url = baseURL() + "challenge/" + httpChalenge.challengeID;
            challenges.Add(httpChalenge);
          }
          if (!IISAppSettings.HasKey("Disable-DNS-Chalenge"))
          {
            Challenge dnsChalenge = _context.Challenge.Where(q => q.authID == retAuth.authID && q.type == net.Challenge.ChallengeType.dns01).FirstOrDefault();
            if (dnsChalenge == null)
            {
              dnsChalenge = new Challenge()
              {
                authID = retAuth.authID,
                challengeID = generateID(),
                type = acme.net.Challenge.ChallengeType.dns01,
                token = generateToken()
              };
              _context.Challenge.Add(dnsChalenge);
            }
            dnsChalenge.url = baseURL() + "challenge/" + dnsChalenge.challengeID;
            challenges.Add(dnsChalenge);
          }
          if (!IISAppSettings.HasKey("Disable-TLSALPN-Challenge"))
          {
            throw new NotImplementedException();
            Challenge tlsChalenge = _context.Challenge.Where(q => q.authID == retAuth.authID && q.type == net.Challenge.ChallengeType.tlsalpn01).FirstOrDefault();
            if (tlsChalenge == null)
            {
              tlsChalenge = new Challenge()
              {
                authID = retAuth.authID,
                challengeID = generateID(),
                type = acme.net.Challenge.ChallengeType.tlsalpn01,
                token = generateToken()
              };
              _context.Challenge.Add(tlsChalenge);
            }
            tlsChalenge.url = baseURL() + "challenge/" + tlsChalenge.challengeID;
            challenges.Add(tlsChalenge);
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
            throw new AcmeException() { type = AcmeError.ErrorType.serverInternal };
          }
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
  }
}
