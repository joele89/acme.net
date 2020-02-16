using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace acme.net
{
  public class Directory
  {
    [Newtonsoft.Json.JsonRequired]
    public String newNonce;
    [Newtonsoft.Json.JsonRequired]
    public String newAccount;
    [Newtonsoft.Json.JsonRequired]
    public String newOrder;
    public String newAuthz;
    [Newtonsoft.Json.JsonRequired]
    public String revokeCert;
    [Newtonsoft.Json.JsonRequired]
    public String keyChange;
    public Meta meta;
    public class Meta
    {
      public String termsOfService;
      public String website;
      public String[] caaIdentities;
      public Boolean externalAccountRequired;
    }
  }
}
