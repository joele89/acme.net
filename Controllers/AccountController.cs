using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using acme.net;

namespace acme.net.Controllers
{
  [Route("[controller]")]
  [ApiController]
  public class AccountController : ControllerBase
  {
    private readonly AcmeContext _context;
    public AccountController(AcmeContext context)
    {
      _context = context;
    }

    // GET: Account/b4R1cgUzETpj
    [HttpGet("{id}")]
    public async Task<ActionResult<Account>> GetAccount(string id)
    {
      Account account = await _context.Account.FindAsync(id);
      account.key = await _context.AccountKey.FindAsync(id);

      if (account == null)
      {
        return NotFound();
      }
      account.baseUrl = baseURL();
      return account;
    }

    // POST: Accounts/b4R1cgUzETpj
    // To protect from overposting attacks, please enable the specific properties you want to bind to, for
    // more details see https://aka.ms/RazorPagesCRUD.
    [HttpPost("{id}")]
    public ActionResult<Account> PostAccount(string id, AcmeJWT message)
    {
      try
      {
        if (message.validate(_context, out Account refAccount))
        {
          refAccount.baseUrl = baseURL();
          if (message.encodedPayload != null && message.encodedPayload != "")
          {
            AccountStub accountStub = Newtonsoft.Json.JsonConvert.DeserializeObject<AccountStub>(message.encodedPayload);

            if (id != refAccount.accountID)
            {
              return BadRequest(new AcmeError() { type = AcmeError.ErrorType.malformed });
            }
            if (accountStub.status != null && accountStub.status != Account.AccountStatus.valid)
            {
              refAccount.status = Account.AccountStatus.deactivated;
              _context.Entry(refAccount).State = EntityState.Modified;
            }
            if (accountStub.contact != null)
            {
              _context.Contact.RemoveRange(_context.Contact.Where(q => q.accountID == refAccount.accountID));
              foreach (string c in accountStub.contact)
              {
                if (Regex.Match(c, "/mailto:\\s*.*/i").Success)
                  _context.Contact.Add(new Contact() { accountID = refAccount.accountID, contact = c });
              }
              _context.Entry(refAccount).State = EntityState.Modified;
            }
            _context.SaveChanges();
            return refAccount;
          } else
          {
            return refAccount;
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
