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
  public class OrderController : ControllerBase
  {

    private readonly AcmeContext _context;
    public OrderController(AcmeContext context)
    {
      _context = context;
    }
    [HttpPost("{acctID}/{orderID}")]
    public ActionResult<Order> Post(string acctID, string orderID, [FromBody] AcmeJWT message)
    {
      try
      {
        if (message.validate(_context, out Account refAccount) && acctID == refAccount.accountID)
        {
          Order order = _context.Order.Find(orderID);
          Response.Headers.Add("Replay-Nonce", generateNonce());
          order.finalize = baseURL() + "finalize/" + acctID + "/" + orderID;

          Authorization[] authz = _context.Authorization.Where(q => q.orderID == order.orderID).ToArray();

          List<OrderStub> identities = new List<OrderStub>();
          List<String> authList = new List<String>();

          int pendingCount = authz.Where(q => q.status == Authorization.AuthorizationStatus.pending).Count();
          int validCount = authz.Where(q => q.status == Authorization.AuthorizationStatus.valid).Count();
          int invalidCount = authz.Where(q => q.status == Authorization.AuthorizationStatus.invalid).Count();
          int deactivatedCount = authz.Where(q => q.status == Authorization.AuthorizationStatus.deactivated).Count();
          int expiredCount = authz.Where(q => q.status == Authorization.AuthorizationStatus.expired).Count();
          int revokedCount = authz.Where(q => q.status == Authorization.AuthorizationStatus.revoked).Count();

          if (validCount >= authz.Count()) order.status = Order.OrderStatus.ready;
          if (pendingCount > 0) order.status = Order.OrderStatus.pending;
          if (invalidCount > 0 || deactivatedCount > 0 || expiredCount > 0 || revokedCount > 0) order.status = Order.OrderStatus.invalid;

          foreach (Authorization orderIdentity in authz)
          {
            identities.Add(new OrderStub() { value = orderIdentity.value, type = orderIdentity.type });
            authList.Add(baseURL() + "authorization/" + orderIdentity.authID);
          }
          order.identifiers = identities.ToArray();
          order.authorizations = authList.ToArray();

          if (order.status == Order.OrderStatus.processing)
          {
            Response.Headers.Add("Retry-After", "15");
          }
          if (order.status == Order.OrderStatus.ready)
          {
            Response.Headers.Add("Retry-After", "15");
            AcmeError e = CAInterface.submitCSR(_context, order);
            if (e != null)
            {
              Response.StatusCode = 500;
              return new ObjectResult(e);
            }
          }
          if (order.status == Order.OrderStatus.valid)
          {
            order.certificateURL = baseURL() + "cert/" + acctID + "/" + orderID;
          }
          return order;
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
