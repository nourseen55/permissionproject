using Domain.Entities;
using Microsoft.AspNetCore.Authorization;

namespace permissionproject.Permission
{
    public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
    {
        protected override  async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
        {
            if (context.User == null) return;
            var permission = context.User.Claims.Where(x=>x.Type==Helper.Permession &&
            x.Value==requirement.Permission&&x.Issuer=="LOCAL AUTHORITY");
            if (permission.Any())
            {
                context.Succeed(requirement);
                return;
            }
        }
    }
}
