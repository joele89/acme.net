using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace acme.net
{
  public class AcmeError
  {
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
    [Newtonsoft.Json.JsonRequired]
    public ErrorType type;
    [Newtonsoft.Json.JsonRequired]
    public String detail;
    public String instance;
    public string reference;
    public AcmeError[] subproblems;
    public enum ErrorType : Int32
    {
      [System.Runtime.Serialization.EnumMember()]
      none,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:accountDoesNotExist")]
      accountDoesNotExist,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:alreadyRevoked")]
      alreadyRevoked,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:badCSR")]
      badCSR,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:badNonce")]
      badNonce,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:badPublicKey")]
      badPublicKey,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:badRevocationReason")]
      badRevocationReason,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:badSignatureAlgorithm")]
      badSignatureAlgorithm,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:caa")]
      caa,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:compound")]
      compound,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:connection")]
      connection,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:dns")]
      dns,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:externalAccountRequired")]
      externalAccountRequired,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:incorrectResponse")]
      incorrectResponse,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:invalidContact")]
      invalidContact,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:malformed")]
      malformed,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:orderNotReady")]
      orderNotReady,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:rateLimited")]
      rateLimited,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:rejectedIdentifier")]
      rejectedIdentifier,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:serverInternal")]
      serverInternal,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:tls")]
      tls,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:unauthorized")]
      unauthorized,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:unsupportedContact")]
      unsupportedContact,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:unsupportedIdentifier")]
      unsupportedIdentifier,
      [System.Runtime.Serialization.EnumMember(Value = "urn:ietf:params:acme:error:userActionRequired")]
      userActionRequired
    }
  }
  public class AcmeException : System.Exception
  {
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
    [Newtonsoft.Json.JsonRequired]
    public AcmeError.ErrorType type;
    [Newtonsoft.Json.JsonRequired]
    public String detail;
    public String instance;
    public string reference;
    public AcmeError[] subproblems;
  }
}
