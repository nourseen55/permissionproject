using Infrastructure.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace permissionproject.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin,SuperAdmin")]

    public class RolesController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        public RolesController(RoleManager<IdentityRole> roleManager) {
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            var roles = new RolesVM()
            {
                Roles = _roleManager.Roles.OrderBy(x => x.Name).ToList(),
            };
            return View(roles);
        }
    }
}
