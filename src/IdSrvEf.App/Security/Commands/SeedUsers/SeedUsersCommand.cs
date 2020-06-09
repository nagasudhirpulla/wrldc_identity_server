using IdSrvEf.Core.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace IdSrvEf.App.Security.Commands.SeedUsers
{
    public class SeedUsersCommand : IRequest<bool>
    {
        public class SeedUsersCommandHandler : IRequestHandler<SeedUsersCommand, bool>
        {
            private readonly UserManager<ApplicationUser> _userManager;
            private readonly RoleManager<IdentityRole> _roleManager;
            private readonly IdentityInit _identityInit;

            public SeedUsersCommandHandler(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IdentityInit identityInit)
            {
                _userManager = userManager;
                _roleManager = roleManager;
                _identityInit = identityInit;
            }

            public async Task<bool> Handle(SeedUsersCommand request, CancellationToken cancellationToken)
            {
                // seed roles
                await SeedUserRoles(_roleManager);
                // seed admin user
                await SeedAdminUser(_userManager);
                // seed guest user
                await SeedGuestUser(_userManager);
                return true;
            }

            /**
             * This method seeds admin user
             * **/
            public async Task SeedAdminUser(UserManager<ApplicationUser> userManager)
            {
                string AdminUserName = _identityInit.AdminUserName;
                string AdminEmail = _identityInit.AdminEmail;
                string AdminPassword = _identityInit.AdminPassword;

                // check if admin user doesn't exist
                if ((await userManager.FindByNameAsync(AdminUserName)) == null)
                {
                    // create desired admin user object
                    ApplicationUser user = new ApplicationUser
                    {
                        UserName = AdminUserName,
                        Email = AdminEmail,
                    };

                    // push desired admin user object to DB
                    IdentityResult result = await userManager.CreateAsync(user, AdminPassword);

                    if (result.Succeeded)
                    {
                        await userManager.AddToRoleAsync(user, SecurityConstants.AdminRoleString);
                    }
                }
            }

            /**
             * This method seeds guest user
             * **/
            public async Task SeedGuestUser(UserManager<ApplicationUser> userManager)
            {
                string GuestUserName = _identityInit.GuestUserName;
                string GuestEmail = _identityInit.GuestEmail;
                string GuestPassword = _identityInit.GuestPassword;

                // check if admin user doesn't exist
                if ((await userManager.FindByNameAsync(GuestUserName)) == null)
                {
                    // create desired admin user object
                    ApplicationUser user = new ApplicationUser
                    {
                        UserName = GuestUserName,
                        Email = GuestEmail,
                    };

                    // push desired admin user object to DB
                    IdentityResult result = await userManager.CreateAsync(user, GuestPassword);

                    if (result.Succeeded)
                    {
                        await userManager.AddToRoleAsync(user, SecurityConstants.GuestRoleString);
                    }
                }
            }

            /**
             * This method seeds roles
             * **/
            public async Task SeedUserRoles(RoleManager<IdentityRole> roleManager)
            {
                List<string> desiredRoles = new List<string>() { SecurityConstants.GuestRoleString, SecurityConstants.AdminRoleString };
                foreach (string roleName in desiredRoles)
                {
                    // check if role doesn't exist
                    if (!await roleManager.RoleExistsAsync(roleName))
                    {
                        // create desired role object
                        IdentityRole role = new IdentityRole
                        {
                            Name = roleName,
                        };
                        // push desired role object to DB
                        IdentityResult roleResult = await roleManager.CreateAsync(role);
                    }
                }
            }
        }
    }
}