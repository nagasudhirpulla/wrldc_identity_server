namespace IdSrvEf.Web.Areas.Identity.Pages.Account
{
    public partial class LoginModel
    {
        public class ExternalProvider
        {
            public string DisplayName { get; set; }
            public string AuthenticationScheme { get; set; }
        }
    }
}
