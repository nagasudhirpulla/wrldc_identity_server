using System;
using System.Text;

namespace IdSrvEf.App.Security
{
    public class IdentityInit
    {
        public string AdminEmail { get; set; }
        public string AdminPassword { get; set; }
        public string AdminUserName { get; set; }
        public string GuestEmail { get; set; }
        public string GuestPassword { get; set; }
        public string GuestUserName { get; set; }
    }
}
