using jwtAuth.Models;
using jwtAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace jwtAuth.Controllers
{
    public class AuthController : Controller
    {
        private readonly AuthService _authService;

        public AuthController(AuthService authService)
        {
            _authService = authService;
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View(new LoginViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            if (model == null)
            {
                return BadRequest("Invalid login data");
            }
            if (string.IsNullOrEmpty(model.UserName) || string.IsNullOrEmpty(model.Password))
            {
                return BadRequest("Username and password are required");
            }
            var user = new User(
                1,
                model.UserName,
                "Bruno Bernardes",
                "bruno@gmail.com",
                model.Password,
                "admin" 
            );

            if (user.Username == null)
            {
                // Xử lý trường hợp user là null
                return BadRequest("User not found");
            }
            var token = _authService.Create(user);

            if (token != null)
            {
                Response.Cookies.Append("jwt", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                });

                return RedirectToAction("AdminDashboard", "Home");
            }
            else
            {
                // Xử lý lỗi nếu token là null
                return BadRequest("Failed to generate JWT token");
            }
        }
       // Chỉ cho phép người dùng có quyền "admin" truy cập vào tuyến đường
       
    }
}
