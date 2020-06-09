using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdSrvEf.Core.Entities;
using IdSrvEf.Infra.IdentityServer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace IdSrvEf.Web.Areas.Identity.Pages.Account
{
    public class LoggedOutModel : PageModel
    {
        public string PostLogoutRedirectUri { get; set; }
        public string ClientName { get; set; }
        public string SignOutIframeUrl { get; set; }

        public bool AutomaticRedirectAfterSignOut { get; set; }

        public string LogoutId { get; set; }
        public bool TriggerExternalSignout => ExternalAuthenticationScheme != null;
        public string ExternalAuthenticationScheme { get; set; }

        private readonly IIdentityServerInteractionService _interaction;

        public LoggedOutModel(IIdentityServerInteractionService interaction)
        {
            _interaction = interaction;
        }

        public async Task OnGet(string logoutId)
        {
            await BuildLoggedOutViewModelAsync(logoutId);
        }

        private async Task BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut;
            PostLogoutRedirectUri = logout?.PostLogoutRedirectUri;
            ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName;
            SignOutIframeUrl = logout?.SignOutIFrameUrl;
            LogoutId = logoutId;

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        ExternalAuthenticationScheme = idp;
                    }
                }
            }
            return;
        }
    }
}
