using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace acme.net
{
  public class Account
  {
    AcmeContext _context;
    [Newtonsoft.Json.JsonIgnore]
    public string baseUrl;
    public Account(AcmeContext context)
    {
      _context = context;
    }

    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Key]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(12) COLLATE SQL_Latin1_General_CP1_CS_AS")]
    public string accountID { get; set; }
    public Key key { get; set; }
    [Newtonsoft.Json.JsonRequired]
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
    public AccountStatus status { get; set; }
    public string[] contact { get { return _context.Contact.Where(q => q.accountID == this.accountID).Select(q => q.contact).ToArray(); } }
    public bool? termsOfServiceAgreed { get; set; }
    public Object externalAccountBinding;
    [Newtonsoft.Json.JsonRequired]
    public string orders { get { return baseUrl + "account/" + accountID + "/orders"; } }

    public enum AccountStatus : int
    {
      valid,
      deactivated,
      revoked
    }
    [System.ComponentModel.DataAnnotations.Schema.Table("AccountKey")]
    public class Key : JWK
    {
      [Newtonsoft.Json.JsonIgnore]
      [System.ComponentModel.DataAnnotations.Key]
      [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(12) COLLATE SQL_Latin1_General_CP1_CS_AS")]
      public string accountID { get; set; }

      public static Key FromJWK(JWK jwk)
      {
        switch (jwk.kty)
        {
          case "RSA":
            Key rsa_k = new Key()
            {
              n = jwk.n,
              e = jwk.e,
              kty = jwk.kty
            };
            return rsa_k;
          case "EC":
            Key ec_k = new Key()
            {
              kty = jwk.kty,
              crv = jwk.crv,
              x = jwk.x,
              y = jwk.y
            };
            return ec_k;
          default:
            throw new NotImplementedException();
        }
      }
    }
  }

  public class AccountStub
  {
    public String[] contact;
    public Boolean? termsOfServiceAgreed;
    public Boolean? onlyReturnExisting;
    public Object externalAccountBinding;
    public Account.AccountStatus? status;
  }
}
