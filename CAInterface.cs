using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace acme.net
{

  public class CAInterface
  {
    static class Constants
    {
      public const int CR_DISP_DENIED = 0x2;
      public const int CR_DISP_ISSUED = 0x3;
      public const int CR_DISP_UNDER_SUBMISSION = 0x5;
    }
    //TODO: Make this async
    public static AcmeError submitCSR(AcmeContext context, Order order)
    {

      order.status = Order.OrderStatus.processing;
      context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
      context.SaveChanges();

      CERTENROLLLib.CX509CertificateRequestPkcs10 certreq = new CERTENROLLLib.CX509CertificateRequestPkcs10();
      certreq.InitializeDecode(order.csr);
      string csrAlgo = certreq.PublicKey.Algorithm.FriendlyName;

      if (!IISAppSettings.HasKey(csrAlgo + "-CAConfig")) return new AcmeError() { type = AcmeError.ErrorType.badCSR, detail = "Certificate Algorithm '" + csrAlgo + "' is not supported by this CA" };

      int ret = 0;
      CERTCLILib.CCertRequest client = new CERTCLILib.CCertRequest();
      try
      {
        if (IISAppSettings.HasKey(csrAlgo + "-CAConfig-User") && IISAppSettings.HasKey(csrAlgo + "-CAConfig-Pass"))
        {
          client.SetCredential(0x0, CERTCLILib.X509EnrollmentAuthFlags.X509AuthUsername, IISAppSettings.GetValue(csrAlgo + "-CAConfig-User"), IISAppSettings.GetValue(csrAlgo + "-CAConfig-Pass"));
        }
        if (IISAppSettings.HasKey(csrAlgo + "-CACertTemplate"))
        {
          ret = client.Submit(0x0, "-----BEGIN NEW CERTIFICATE REQUEST-----" + order.csr + "-----END NEW CERTIFICATE REQUEST-----", "CertificateTemplate:" + IISAppSettings.GetValue(csrAlgo + "-CACertTemplate"), IISAppSettings.GetValue(csrAlgo + "-CAConfig"));
        }
        else
        {
          ret = client.Submit(0x0, "-----BEGIN NEW CERTIFICATE REQUEST-----" + order.csr + "-----END NEW CERTIFICATE REQUEST-----", null, IISAppSettings.GetValue(csrAlgo + "-CAConfig"));
        }
      }
      catch (Exception ex)
      {
        order.status = Order.OrderStatus.ready;
        context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
        context.SaveChanges();
        return new AcmeError()
        {
          detail = "Error communicating with upstream CA",
          type = AcmeError.ErrorType.serverInternal,
          subproblems = new AcmeError[] {
            new AcmeError()
            {
              type = AcmeError.ErrorType.serverInternal,
              detail = ex.Message,
            }
          }
        };
      }

      try
      {
        switch (ret)
        {
          case Constants.CR_DISP_ISSUED:
            {
              order.caReqID = client.GetRequestId();
              break;
            }
          case Constants.CR_DISP_DENIED:
            {
              order.caReqID = client.GetRequestId();
              order.status = Order.OrderStatus.invalid;
              context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
              context.SaveChanges();
              return new AcmeError()
              {
                detail = "CA denied the request",
                type = AcmeError.ErrorType.serverInternal,
              };
              break;
            }
          case Constants.CR_DISP_UNDER_SUBMISSION:
            {
              order.caReqID = client.GetRequestId();
              order.status = Order.OrderStatus.invalid;
              context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
              context.SaveChanges();
              return new AcmeError()
              {
                detail = "Upstream CA is not configured for auto issuance",
                type = AcmeError.ErrorType.serverInternal,
              };
              break;
            }
        }
      }
      catch (Exception ex)
      {
        order.status = Order.OrderStatus.ready;
        context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
        context.SaveChanges();
        return new AcmeError()
        {
          detail = "Error communicating with upstream CA",
          type = AcmeError.ErrorType.serverInternal,
          subproblems = new AcmeError[] {
            new AcmeError()
            {
              type = AcmeError.ErrorType.serverInternal,
              detail = ex.Message,
            }
          }
        };
      }
      try
      {
        order.certificate = client.GetCertificate(0x0);
        order.status = Order.OrderStatus.valid;
        context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
        context.SaveChanges();
      }
      catch (Exception ex)
      {
        order.status = Order.OrderStatus.ready;
        context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
        context.SaveChanges();
        return new AcmeError()
        {
          detail = "Error communicating with upstream CA",
          type = AcmeError.ErrorType.serverInternal,
          subproblems = new AcmeError[] {
            new AcmeError()
            {
              type = AcmeError.ErrorType.serverInternal,
              detail = ex.Message,
            }
          }
        };
      }
      return null;
    }

    public static AcmeError revokeCertificate(Order order, int Reason)
    {
      CERTENROLLLib.CX509CertificateRequestPkcs10 certreq = new CERTENROLLLib.CX509CertificateRequestPkcs10();
      certreq.InitializeDecode(order.csr);
      string csrAlgo = certreq.PublicKey.Algorithm.FriendlyName;

      if (IISAppSettings.HasKey(csrAlgo + "-RevokeURL"))
      {
        string FullURL = IISAppSettings.GetValue(csrAlgo + "-RevokeURL").Replace("{CARequestID}", order.caReqID.ToString()).Replace("{Reason}", Reason.ToString());
        System.Net.HttpWebRequest Client = (HttpWebRequest)System.Net.HttpWebRequest.Create(FullURL);
        Client.PreAuthenticate = true;
        System.Net.CredentialCache credCache = new System.Net.CredentialCache();
        credCache.Add(new System.Uri(FullURL), "Basic", new System.Net.NetworkCredential(IISAppSettings.GetValue(csrAlgo + "-CAConfig-User"), IISAppSettings.GetValue(csrAlgo + "-CAConfig-Pass")));
        Client.Credentials = credCache;
        Client.Method = "GET";
        try
        {
          System.Net.HttpWebResponse Resp = (System.Net.HttpWebResponse)Client.GetResponse();
        }
        catch (Exception ex) {
          return new AcmeError()
          {
            detail = "Error revoking certificate",
            type = AcmeError.ErrorType.serverInternal,
            subproblems = new AcmeError[]
            {
              new AcmeError()
              {
                type = AcmeError.ErrorType.serverInternal,
                detail = ex.Message
              }
            }
          };
        }
      }
      return null;
    }
  }
}
