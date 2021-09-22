using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;

namespace acme.net
{
  public class Startup
  {
    public Startup(IConfiguration configuration)
    {
      Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
      services.AddDbContext<AcmeContext>(opt => opt.UseSqlServer(IISAppSettings.GetValue("SQLConnectionString")));
      services.AddControllers().AddNewtonsoftJson(options =>
      {
        options.SerializerSettings.NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore;
        options.SerializerSettings.DateTimeZoneHandling = Newtonsoft.Json.DateTimeZoneHandling.Utc;
      });
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
      if (env.IsDevelopment())
      {
        app.UseDeveloperExceptionPage();
      }
      else
      {
        app.UseHttpsRedirection();
      }

      app.UseRouting();

      app.UseAuthorization();

      app.UseEndpoints(endpoints =>
      {
        endpoints.MapControllers();
      });

      using (var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
      {
        var context = serviceScope.ServiceProvider.GetRequiredService<AcmeContext>();
        if (context.Database.EnsureCreated())
        {
          context.Database.ExecuteSqlRaw("EXEC [ACMEv2_2].sys.sp_addextendedproperty @Name=N'SchemaVersion', @Value=N'1.0.1.0'");
        }
        else
        {
          System.Data.Common.DbCommand dbCommand = context.Database.GetDbConnection().CreateCommand();
          dbCommand.CommandText = "SELECT value FROM sys.extended_properties WHERE name='SchemaVersion'";
          dbCommand.Connection.Open();
          string schemaVersion = (string)dbCommand.ExecuteScalar();
          dbCommand.Connection.Close();
          switch (schemaVersion)
          {
            case null:
              //<=1.0.0 schema
              context.Database.ExecuteSqlRaw("EXEC [ACMEv2_2].sys.sp_addextendedproperty @Name=N'SchemaVersion', @Value=N'1.0.0.0'");
              goto case "1.0.0.0";
            case "1.0.0.0":
              context.Database.ExecuteSqlRaw("BEGIN TRANSACTION;" +
                                             "ALTER TABLE dbo.AccountKey ADD" +
                                             "  crv varchar(10) NULL," +
                                             "  x varchar(2000) COLLATE SQL_Latin1_General_CP1_CS_AS NULL," +
                                             "  y varchar(2000) COLLATE SQL_Latin1_General_CP1_CS_AS NULL;" +
                                             "ALTER TABLE dbo.AccountKey SET(LOCK_ESCALATION = TABLE);" +
                                             "EXEC[ACMEv2_2].sys.sp_updateextendedproperty @Name = N'SchemaVersion', @Value = N'1.0.1.0';" +
                                             "COMMIT");
              goto case "1.0.1.0";
            case "1.0.1.0":
              //current schema version, continue from here
              break;
            default:
              throw new ArgumentException("Incompatable Database Schema");
              break;
          }
        }
      }
    }
  }
}
