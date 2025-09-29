using Domain.Constants;
using Infrastructure.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace permissionproject.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin,SuperAdmin")]

    public class PermissionController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        public PermissionController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }
        public async Task<IActionResult> Index(string RoleId)
        {
            var role = await _roleManager.FindByIdAsync(RoleId);
            var claims = _roleManager.GetClaimsAsync(role).Result.Select(x => x.Value).ToList();
            var allPermissions =Permessions.PermissionList()
                .Select(x => new RolesClaimsVM { Value = x }).ToList();

            foreach (var permission in allPermissions)
                if (claims.Any(x => x == permission.Value))
                    permission.Selected = true;

            return View(new PermissionVM
            {
                RoleId = RoleId,
                RoleName = role.Name,
                RolesClaims = allPermissions
            });
        }

    }
}
