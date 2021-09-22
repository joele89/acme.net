using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

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
      switch (header.alg)
      {
        case "RS256":
          return validate_rs256(targetJWK.n, targetJWK.e);
        case "ES256":
        case "ES384":
        case "ES521":
          return validate_es(targetJWK.crv, targetJWK.x, targetJWK.y);
        default:
          throw new AcmeException() { type = AcmeError.ErrorType.badSignatureAlgorithm, detail = header.alg, reference = "JWT:51" };
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
      switch (header.alg)
      {
        case "RS256":
          return validate_rs256(targetJWK.n, targetJWK.e);
        case "ES256":
        case "ES384":
        case "ES521":
          return validate_es(targetJWK.crv, targetJWK.x, targetJWK.y);
        default:
          throw new AcmeException() { type = AcmeError.ErrorType.badSignatureAlgorithm, detail = header.alg, reference = "JWT:85" };
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

    bool validate_es(string crv, string x, string y)
    {
      System.Security.Cryptography.ECCurve curve;
      System.Security.Cryptography.HashAlgorithmName hashName;
      switch (crv)
      {
        case "P-256":
          curve = System.Security.Cryptography.ECCurve.NamedCurves.nistP256;
          hashName = System.Security.Cryptography.HashAlgorithmName.SHA256;
          break;
        case "P-384":
          curve = System.Security.Cryptography.ECCurve.NamedCurves.nistP384;
          hashName = System.Security.Cryptography.HashAlgorithmName.SHA384;
          break;
        case "P-521":
          curve = System.Security.Cryptography.ECCurve.NamedCurves.nistP521;
          hashName = System.Security.Cryptography.HashAlgorithmName.SHA512;
          break;
        default:
          throw new AcmeException() { type = AcmeError.ErrorType.badPublicKey };
      }
      System.Security.Cryptography.ECDsa es = System.Security.Cryptography.ECDsa.Create();
      es.ImportParameters(
        new System.Security.Cryptography.ECParameters()
        {
          Curve = curve,
          Q = new System.Security.Cryptography.ECPoint()
          {
            X = Base64UrlEncoder.DecodeBytes(x),
            Y = Base64UrlEncoder.DecodeBytes(y)
          }
        }
        );
      return es.VerifyData(System.Text.Encoding.UTF8.GetBytes(this.encodedJWTHeader + "." + this.encodedPayload), Base64UrlEncoder.DecodeBytes(this.signature), hashName);
    }

    static public string calculateAccountHash(Account account)
    {
      JWK jwk;

      switch (account.key.kty)
      {
        case "RSA":

          //System.Security.Cryptography.RSACryptoServiceProvider rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
          //rsa.ImportParameters(
          //  new System.Security.Cryptography.RSAParameters()
          //  {
          //    Modulus = Base64UrlEncoder.DecodeBytes(account.key.n),
          //    Exponent = Base64UrlEncoder.DecodeBytes(account.key.e)
          //  });

          jwk = new RSA_JWK()
          {
            e = account.key.e,
            kty = account.key.kty,
            n = account.key.n
          };
          return calculateTokenHash(Newtonsoft.Json.JsonConvert.SerializeObject(jwk), "SHA256");
        case "EC":
          jwk = new EC_JWK()
          {
            crv = account.key.crv,
            kty = account.key.kty,
            x = account.key.x,
            y = account.key.y
          };
          string jsonJWK = Newtonsoft.Json.JsonConvert.SerializeObject(jwk);
          return calculateTokenHash(jsonJWK, jwk.GetHashName());
        default:
          throw new AcmeException() { type = AcmeError.ErrorType.badPublicKey };
      }
    }

    static public string calculateTokenHash(string token, string hashName)
    {
      System.Security.Cryptography.HashAlgorithm hasher = System.Security.Cryptography.HashAlgorithm.Create(hashName);

      byte[] hash = hasher.ComputeHash(System.Text.Encoding.UTF8.GetBytes(token));
      return Base64UrlEncoder.Encode(hash);
    }

  }
  public class JWTHeader
  {
    public String alg;
    public String kid;
    JWK _jwk;
    public JWK jwk
    {
      get
      {
        if (_jwk == null) { return _jwk; }
        return _jwk.kty switch
        {
          "RSA" => new RSA_JWK() { e = _jwk.e, kty = _jwk.kty, n = _jwk.n },
          "EC" => new EC_JWK() { crv = _jwk.crv, kty = _jwk.kty, x = _jwk.x, y = _jwk.y },
          _ => null,
        };
      }
      set
      {
        _jwk = value;
      }
    }
    public String nonce;
    public String url;
  }
  public class JWK
  {
    [Newtonsoft.Json.JsonProperty(Order = 1)]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(10)")]
    virtual public String crv { get; set; }


    [Newtonsoft.Json.JsonProperty(Order = 1)]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(10) COLLATE SQL_Latin1_General_CP1_CS_AS")]
    virtual public String e { get; set; }


    [Newtonsoft.Json.JsonProperty(Order = 2)]
    [Newtonsoft.Json.JsonRequired]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(10)")]
    virtual public String kty { get; set; }


    [Newtonsoft.Json.JsonProperty(Order = 3)]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(2000) COLLATE SQL_Latin1_General_CP1_CS_AS")]
    virtual public String n { get; set; }


    [Newtonsoft.Json.JsonProperty(Order = 3)]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(2000) COLLATE SQL_Latin1_General_CP1_CS_AS")]
    virtual public String x { get; set; }


    [Newtonsoft.Json.JsonProperty(Order = 4)]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(2000) COLLATE SQL_Latin1_General_CP1_CS_AS")]
    virtual public String y { get; set; }



    public string GetHashName()
    {
      return this.kty switch
      {
        "RSA" => "SHA256",
        "EC" => this.crv switch
        {
          "P-256" => "SHA256",
          "P-384" => "SHA384",
          "P-521" => "SHA512",
          _ => "",
        },
        _ => "",
      };
    }
  }
  public class EC_JWK : JWK
  {
    [Newtonsoft.Json.JsonRequired]
    override public String crv { get; set; }
    [Newtonsoft.Json.JsonRequired]
    override public String x { get; set; }
    [Newtonsoft.Json.JsonRequired]
    override public String y { get; set; }
    [Newtonsoft.Json.JsonIgnore]
    override public String e { get; set; }
    [Newtonsoft.Json.JsonIgnore]
    override public String n { get; set; }
  }
  public class RSA_JWK : JWK
  {
    [Newtonsoft.Json.JsonRequired]
    override public String e { get; set; }
    [Newtonsoft.Json.JsonRequired]
    override public String n { get; set; }
    [Newtonsoft.Json.JsonIgnore]
    override public String crv { get; set; }
    [Newtonsoft.Json.JsonIgnore]
    override public String x { get; set; }
    [Newtonsoft.Json.JsonIgnore]
    override public String y { get; set; }
  }

}
