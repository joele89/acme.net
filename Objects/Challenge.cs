using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace acme.net
{
  public class Challenge
  {
    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(12)")]
    public string challengeID { get; set; }
    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Required]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(12)")]
    public string authID { get; set; }
    [Newtonsoft.Json.JsonRequired]
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
    public ChallengeType type { get; set; }
    [Newtonsoft.Json.JsonRequired]
    public string url;
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
    public ChallengeStatus status { get; set; }
    [Newtonsoft.Json.JsonRequired]
    [System.ComponentModel.DataAnnotations.Required]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(44)")]
    public string token { get; set; }
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.IsoDateTimeConverter))]
    [Newtonsoft.Json.JsonProperty(DefaultValueHandling = Newtonsoft.Json.DefaultValueHandling.Ignore)]
    public DateTimeOffset? validated { get; set; }
    [Newtonsoft.Json.JsonProperty(DefaultValueHandling = Newtonsoft.Json.DefaultValueHandling.Ignore)]
    public AcmeError error;
    [Newtonsoft.Json.JsonIgnore]
    public AcmeError.ErrorType? errorType { get { if (error == null) { return null; } else { return error.type; } } set { if (value == null) { error = null; } else { if (error == null) { error = new AcmeError(); }; error.type = value.Value; } } }
    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "TEXT")]
    public string errorDetail {get { if (error == null) { return null; } else { return error.detail; } } set { if (value == null) { error = null; } else { if (error == null) { error = new AcmeError(); }; error.detail = value; } } }

    public enum ChallengeType : int
    {
      [System.Runtime.Serialization.EnumMember(Value = "http-01")]
      http01,
      [System.Runtime.Serialization.EnumMember(Value = "dns-01")]
      dns01,
      [System.Runtime.Serialization.EnumMember(Value = "tlsalpn-01")]
      tlsalpn01,
    }
    public enum ChallengeStatus : int
    {
      pending,
      processing,
      valid,
      invalid
    }
  }
}
