using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace acme.net
{
  public class AcmeContext : DbContext
  {
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
      modelBuilder.Entity<Contact>().HasKey(c => new { c.accountID, c.contact });
    }

    public AcmeContext(DbContextOptions<AcmeContext> options) : base(options) { }
    
    public virtual DbSet<Account> Account { get; set; }
    public virtual DbSet<Contact> Contact { get; set; }
    public virtual DbSet<Account.Key> AccountKey { get; set; }
    public virtual DbSet<Order> Order { get; set; }
    public virtual DbSet<Authorization> Authorization { get; set; }
    public virtual DbSet<Challenge> Challenge { get; set; }
    public virtual DbSet<IdentifierPreAuth> IdentifierPreAuth { get; set; }
  }
  
  /*
  public class AcmeContextFactory : Microsoft.EntityFrameworkCore.Design.IDesignTimeDbContextFactory<AcmeContext>
  {
    public AcmeContext CreateDbContext(string[] args)
    {
      DbContextOptionsBuilder<AcmeContext> optionsBuilder = new DbContextOptionsBuilder<AcmeContext>();
      optionsBuilder.UseSqlServer(IISAppSettings.GetValue("SQLConnectionString"));
      return new AcmeContext(optionsBuilder.Options);
    }
  }
  */
}
