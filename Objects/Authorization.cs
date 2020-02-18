using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace acme.net
{
  [System.ComponentModel.DataAnnotations.Schema.Table("Authorization")]
  public class Authorization
  {
    public Authorization()
    {
      identifier = new OrderStub();
    }

    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Key]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(12)")]
    public string authID { get; set; }
    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Required]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(12)")]
    public string orderID { get; set; }
    [Newtonsoft.Json.JsonRequired]
    public OrderStub identifier;
    [Newtonsoft.Json.JsonIgnore]
    //[System.ComponentModel.DataAnnotations.Schema.Column("type")]
    public Order.OrderType type { get { return identifier.type; } set { identifier.type = value; } }
    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(500)")]
    public string value { get { return identifier.value; } set { identifier.value = value; } }
    [Newtonsoft.Json.JsonIgnore]
    public DateTimeOffset? notBefore { get { return identifier.notBefore; } set { identifier.notBefore = value; } }
    [Newtonsoft.Json.JsonIgnore]
    public DateTimeOffset? notAfter { get { return identifier.notAfter; } set { identifier.notAfter = value; } }

    [Newtonsoft.Json.JsonRequired]
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
    public AuthorizationStatus? status { get; set; }
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.IsoDateTimeConverter))]
    [Newtonsoft.Json.JsonProperty(DefaultValueHandling = Newtonsoft.Json.DefaultValueHandling.Ignore)]
    public DateTimeOffset? expires { get; set; }
    [Newtonsoft.Json.JsonRequired]
    public Challenge[] challenges;
    public Boolean wildcard { get; set; }

    public enum AuthorizationStatus : int
    {
      pending,
      valid,
      invalid,
      deactivated,
      expired,
      revoked,
    }
  }
}
