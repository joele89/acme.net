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
    public Order Post(string acctID, string orderID, [FromBody] AcmeJWT message)
    {
      if (message.validate(_context, out Account refAccount) && acctID == refAccount.accountID)
      {
        Order order = _context.Order.Find(orderID);
        Response.Headers.Add("Replay-Nonce", generateNonce());
        order.finalize = baseURL() + "finalize/" + acctID + "/" + orderID;

        Authorization[] authz = _context.Authorization.Where(q => q.orderID == order.orderID).ToArray();

        List<OrderStub> identities = new List<OrderStub>();
        List<String> authList = new List<String>();

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
          order.error = CAInterface.submitCSR(_context, order);
        }
        if (order.status == Order.OrderStatus.valid)
        {
          order.certificateURL = baseURL() + "cert/" + acctID + "/" + orderID;
        }
        return order;
      }
      else
      {
        throw new AcmeException() { type = AcmeError.ErrorType.malformed };
      }
    }
  }
}
