using Domain.Entities;
using Infrastructure.Data;
using Infrastructure.Infrastructure;
using Infrastructure.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace permissionproject.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class AccountController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ApplicationDbContext _context;

        public AccountController(RoleManager<IdentityRole> roleManager,
                                 UserManager<ApplicationUser> userManager,
                                 SignInManager<ApplicationUser> signInManager,
                                 ApplicationDbContext dbContext)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _signInManager = signInManager;
            _context = dbContext;
        }

        public IActionResult Registers()
        {
            var model = new RegisterViewModel
            {
                NewRegister = new NewRegister(),
                Roles = _roleManager.Roles.OrderBy(x => x.Name).ToList(),
                Users = _context.Users.OrderBy(x => x.Name).ToList()
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Registers(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (model.NewRegister.ImageFile != null && model.NewRegister.ImageFile.Length > 0)
                {
                    string imageName = Guid.NewGuid().ToString() + Path.GetExtension(model.NewRegister.ImageFile.FileName);
                    var savePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", Helper.PathSaveImageuser);

                    if (!Directory.Exists(savePath))
                        Directory.CreateDirectory(savePath);

                    var filePath = Path.Combine(savePath, imageName);

                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await model.NewRegister.ImageFile.CopyToAsync(stream);
                    }

                    model.NewRegister.userImg = imageName;
                }

                var user = new ApplicationUser
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = model.NewRegister.Name,
                    UserName = model.NewRegister.Email,
                    Email = model.NewRegister.Email,
                    IsActive = model.NewRegister.IsActive,
                    userImg = model.NewRegister.userImg,
                    EmailConfirmed=true
                };

                string defaultRole = "Basic";

                var result = await _userManager.CreateAsync(user, model.NewRegister.Password);

                if (result.Succeeded)
                {
                    if (!await _roleManager.RoleExistsAsync(defaultRole))
                    {
                        await _roleManager.CreateAsync(new IdentityRole(defaultRole));
                    }

                    await _userManager.AddToRoleAsync(user, defaultRole);

                    await _signInManager.SignInAsync(user, isPersistent: false);

                    return RedirectToAction("Index", "Home", new { area = "" });
                }
                else
                {
                    foreach (var err in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, err.Description);
                    }
                    ViewBag.Error = "Failed to create user.";
                }
            }
            else
            {
                ViewBag.Error = "Invalid data.";
            }

            model.Roles = _roleManager.Roles.OrderBy(x => x.Name).ToList();
            model.Users = _context.Users.OrderBy(x => x.Name).ToList();

            return View(model);
        }
        [HttpGet]
        public IActionResult Login()
        {
            return View(new LoginViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null && user.IsActive)
                {
                    var result = await _signInManager.PasswordSignInAsync(
                        user.UserName,
                        model.Password,
                        model.RememberMe,
                        lockoutOnFailure: false
                    );

                    if (result.Succeeded)
                    {
                        return RedirectToAction("Index", "Home", new { area = "" });
                    }
                }

                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            }

            return View(model);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login", "Account", new { area = "Admin" });
        }
    }
}