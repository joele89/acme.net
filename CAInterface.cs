using System;
using System.Collections.Generic;
using System.Linq;
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
    public static AcmeError submitCSR(AcmeContext context, Order order)
    {

      order.status = Order.OrderStatus.processing;
      context.Entry(order).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
      context.SaveChanges();

      int ret = 0;
      CERTCLILib.CCertRequest client = new CERTCLILib.CCertRequest();
      try
      {

        if (IISAppSettings.HasKey("CAConfig-User") && IISAppSettings.HasKey("CAConfig-Pass"))
        {
          client.SetCredential(0x0, CERTCLILib.X509EnrollmentAuthFlags.X509AuthUsername, IISAppSettings.GetValue("CAConfig-User"), IISAppSettings.GetValue("CAConfig-Pass"));
        }
        if (IISAppSettings.HasKey("CACertTemplate"))
        {
          ret = client.Submit(0x0, "-----BEGIN NEW CERTIFICATE REQUEST-----" + order.csr + "-----END NEW CERTIFICATE REQUEST-----", "CertificateTemplate:" + IISAppSettings.GetValue("CACertTemplate"), IISAppSettings.GetValue("CAConfig"));
        }
        else
        {
          ret = client.Submit(0x0, "-----BEGIN NEW CERTIFICATE REQUEST-----" + order.csr + "-----END NEW CERTIFICATE REQUEST-----", null, IISAppSettings.GetValue("CAConfig"));
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
#warning TODO: SubmitCSR as task
    }
  }
}
