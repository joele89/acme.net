using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace acme.net
{
  [System.ComponentModel.DataAnnotations.Schema.Table("AccountContacts")]
  public class Contact
  {
    [Newtonsoft.Json.JsonIgnore]
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(12)")]
    public string accountID { get; set; }
    [System.ComponentModel.DataAnnotations.Schema.Column(TypeName = "VARCHAR(255)")]
    public string contact { get; set; }
  }
}
