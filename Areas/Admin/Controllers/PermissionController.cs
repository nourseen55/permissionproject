using System.Security.Claims;
using Domain.Constants;
using Domain.Entities;
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
            var claims =  _roleManager.GetClaimsAsync(role).Result.Select(x => x.Value).ToList();
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
        [HttpPost]
        [ValidateAntiForgeryToken]
         public async Task<IActionResult> Update(PermissionVM permissionVM)
         {
            var role =await _roleManager.FindByIdAsync(permissionVM.RoleId);
            var allclaims=await _roleManager.GetClaimsAsync(role);
            foreach (var item in allclaims)
                await _roleManager.RemoveClaimAsync(role, item);
            var selectedclaims=permissionVM.RolesClaims.Where(x=>x.Selected).ToList();
            foreach (var item in selectedclaims)
                await _roleManager.AddClaimAsync(role, new Claim(Helper.Permession, item.Value));
          
            return RedirectToAction("Index","Roles");


        }


        }

    
}
