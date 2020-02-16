using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace acme.net
{
  public class OrdersList
  {
    [Newtonsoft.Json.JsonRequired]
    public String[] orders;
  }
  public class Order
  {
    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Key]
    public string orderID { get; set; }
    [Newtonsoft.Json.JsonIgnore]
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
    public String[] authorizations;
    [Newtonsoft.Json.JsonRequired]
    public String finalize;
    [Newtonsoft.Json.JsonIgnore]
    public string csr { get; set; }
    [Newtonsoft.Json.JsonIgnore]
    public String certificate { get; set; }
    [Newtonsoft.Json.JsonProperty(PropertyName = "certificate")]
    public String certificateURL;
    [Newtonsoft.Json.JsonIgnore]
    public int caReqID { get; set; }

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
}
