using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace acme.net
{
  public class Order
  {
    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Key]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(12) COLLATE SQL_Latin1_General_CP1_CS_AS")]
    public string orderID { get; set; }
    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Required]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(12) COLLATE SQL_Latin1_General_CP1_CS_AS")]
    public string accountID { get; set; }
    [Newtonsoft.Json.JsonRequired]
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
    public OrderStatus status { get; set; }
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.IsoDateTimeConverter))]
    [Newtonsoft.Json.JsonProperty(DefaultValueHandling = Newtonsoft.Json.DefaultValueHandling.Ignore)]
    public DateTimeOffset expires { get; set; }
    [Newtonsoft.Json.JsonRequired]
    public OrderStub[] identifiers;
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.IsoDateTimeConverter))]
    [Newtonsoft.Json.JsonProperty(DefaultValueHandling = Newtonsoft.Json.DefaultValueHandling.Ignore)]
    public DateTimeOffset? notBefore { get; set; }
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.IsoDateTimeConverter))]
    [Newtonsoft.Json.JsonProperty(DefaultValueHandling = Newtonsoft.Json.DefaultValueHandling.Ignore)]
    public DateTimeOffset? notAfter { get; set; }
    public AcmeError error;
    [Newtonsoft.Json.JsonRequired]
    public string[] authorizations;
    [Newtonsoft.Json.JsonRequired]
    public string finalize;
    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "TEXT")]
    public string csr { get; set; }
    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "TEXT")]
    public string certificate { get; set; }
    [Newtonsoft.Json.JsonProperty(PropertyName = "certificate")]
    public string certificateURL;
    [Newtonsoft.Json.JsonIgnore]
    public int? caReqID { get; set; }
    [Newtonsoft.Json.JsonIgnore]
    public Revocation.Reason? revocationReason { get; set; }

    public enum OrderStatus : int
    {
      pending,
      ready,
      processing,
      valid,
      invalid,
    }
    public enum OrderType : int
    {
      dns,
    }

  }
  public class Revocation
  {
    public string certificate { get; set; }
    public Reason? reason { get; set; }
    public enum Reason : int
    {
      unspecified = 0,
      keyCompromise = 1,
      caCompromise = 2,
      affiliationChanged = 3,
      superseded = 4,
      cessationOfOperation = 5,
      hold = 6,
      releaseFromCRL = 8,
      unrevoke = -1,
    }
  }
  public class OrderStub
  {
    [Newtonsoft.Json.JsonRequired]
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
    public Order.OrderType type;
    [Newtonsoft.Json.JsonRequired]
    public string value;
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.IsoDateTimeConverter))]
    [Newtonsoft.Json.JsonProperty(DefaultValueHandling = Newtonsoft.Json.DefaultValueHandling.Ignore)]
    public DateTimeOffset? notBefore;
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.IsoDateTimeConverter))]
    [Newtonsoft.Json.JsonProperty(DefaultValueHandling = Newtonsoft.Json.DefaultValueHandling.Ignore)]
    public DateTimeOffset? notAfter;
  }

  public class OrderList
  {
    [Newtonsoft.Json.JsonRequired]
    public OrderStub[] identifiers;
  }
  public class Finalize
  {
    public string resource;
    [Newtonsoft.Json.JsonRequired]
    public string csr;
  }
  public class IdentifierPreAuth
  {
    [System.ComponentModel.DataAnnotations.Key]
    public string identifier { get; set; }
  }
}
