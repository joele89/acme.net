using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
//using System.IdentityModel.Tokens.Jwt;

namespace acme.net
{
  public class AcmeJWT
  {
    [Newtonsoft.Json.JsonProperty("protected")]
    public String encodedJWTHeader;
    [Newtonsoft.Json.JsonProperty("payload")]
    public String encodedPayload;
    [Newtonsoft.Json.JsonProperty("signature")]
    public String signature;

    public bool validate(AcmeContext context)
    {
#warning TODO: validate NONCE issued/not reused.
      string decodedHeader = Base64UrlEncoder.Decode(this.encodedJWTHeader);
      JWTHeader header = Newtonsoft.Json.JsonConvert.DeserializeObject<JWTHeader>(decodedHeader);
      string jsonJWK = Newtonsoft.Json.JsonConvert.SerializeObject(header.jwk);

      JWK targetJWK;

      if (header.kid != null && header.kid != "")
      {
        string[] kid = header.kid.Split("/");
        string acctID = kid[^1];
        Account.Key acctKey = context.AccountKey.Find(acctID);
        targetJWK = acctKey;
      }
      else if (header.jwk != null)
      {
        targetJWK = header.jwk;
      }
      else
      {
        throw new AcmeException() { type = AcmeError.ErrorType.malformed };
      }

      switch (header.alg.ToUpper())
      {
        case "RS256":
          return validate_rs256(targetJWK.n, targetJWK.e);
        default:
          throw new AcmeException() { type = AcmeError.ErrorType.badSignatureAlgorithm };
      }

    }

    public bool validate(AcmeContext context, out Account referenceAccount)
    {
      string decodedHeader = Base64UrlEncoder.Decode(this.encodedJWTHeader);
      JWTHeader header = Newtonsoft.Json.JsonConvert.DeserializeObject<JWTHeader>(decodedHeader);
      string jsonJWK = Newtonsoft.Json.JsonConvert.SerializeObject(header.jwk);

      JWK targetJWK;

      if (header.kid != null && header.kid != "")
      {
        string[] kid = header.kid.Split("/");
        string acctID = kid[^1];
        referenceAccount = context.Account.Find(acctID);
        Account.Key acctKey = context.AccountKey.Find(acctID);
        targetJWK = acctKey;
      }
      else if (header.jwk != null)
      {
        targetJWK = header.jwk;
        referenceAccount = null;
      }
      else
      {
        throw new AcmeException() { type = AcmeError.ErrorType.malformed };
      }

      switch (header.alg.ToUpper())
      {
        case "RS256":
          return validate_rs256(targetJWK.n, targetJWK.e);
        default:
          throw new AcmeException() { type = AcmeError.ErrorType.badSignatureAlgorithm };
      }

    }

    bool validate_rs256(string modulus, string exponent)
    {
      System.Security.Cryptography.RSACryptoServiceProvider rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
      rsa.ImportParameters(
        new System.Security.Cryptography.RSAParameters()
        {
          Modulus = Base64UrlEncoder.DecodeBytes(modulus),
          Exponent = Base64UrlEncoder.DecodeBytes(exponent)
        });

      System.Security.Cryptography.SHA256 sha256 = System.Security.Cryptography.SHA256.Create();
      byte[] hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(this.encodedJWTHeader + "." + this.encodedPayload));

      System.Security.Cryptography.RSAPKCS1SignatureDeformatter rsaDeformatter = new System.Security.Cryptography.RSAPKCS1SignatureDeformatter(rsa);
      rsaDeformatter.SetHashAlgorithm("SHA256");
      return rsaDeformatter.VerifySignature(hash, Base64UrlEncoder.DecodeBytes(this.signature));
    }

    static public string calculateAccountHash(Account account)
    {
      System.Security.Cryptography.RSACryptoServiceProvider rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
      rsa.ImportParameters(
        new System.Security.Cryptography.RSAParameters()
        {
          Modulus = Base64UrlEncoder.DecodeBytes(account.key.n),
          Exponent = Base64UrlEncoder.DecodeBytes(account.key.e)
        });

      JWK jwk = new JWK()
      {
        e = account.key.e,
        kty = account.key.kty,
        n = account.key.n
      };

      string jsonJWK = Newtonsoft.Json.JsonConvert.SerializeObject(jwk);
      return calculateTokenHash(jsonJWK);
    }

    static public string calculateTokenHash(string token)
    {
      System.Security.Cryptography.SHA256 sha256 = System.Security.Cryptography.SHA256.Create();
      byte[] hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(token));
      return Base64UrlEncoder.Encode(hash);
    }

  }
  public class JWTHeader
  {
    public String alg;
    public String kid;
    public JWK jwk;
    public String nonce;
    public String url;
  }
  public class JWK
  {
    [Newtonsoft.Json.JsonRequired]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(10) COLLATE SQL_Latin1_General_CP1_CS_AS")]
    virtual public String e { get; set; }
    [Newtonsoft.Json.JsonRequired]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(10)")]
    virtual public String kty { get; set; }
    [Newtonsoft.Json.JsonRequired]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(2000) COLLATE SQL_Latin1_General_CP1_CS_AS")]
    virtual public String n { get; set; }
  }
}
