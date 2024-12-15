using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace jwtAuth.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult AdminDashboard()
        {
            // Kiểm tra xem token JWT có trong yêu cầu không
            var token = Request.Cookies["jwt"];
            if (string.IsNullOrEmpty(token))
            {
                // Nếu không, chuyển hướng người dùng đến trang đăng nhập
                return RedirectToAction("Login", "Auth");
            }

            // Xác minh token JWT
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(Configuration.PrivateKey);

            try
            {
                // Validate token
                var tokenValidationParameters = new TokenValidationParameters
                {
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = false,
                    ValidateAudience = false
                };

                SecurityToken validatedToken;
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out validatedToken);

                // Lấy danh sách các vai trò từ token
                var roles = principal.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();

                // Kiểm tra xem vai trò "teacher" có trong danh sách không
                if (roles.Contains("manager"))
                {
                    // Nếu có, cho phép truy cập vào trang AdminDashboard
                    return View();
                }
                else
                {

                    var messageError = "Bạn không có quyền thực hiện thao tác này";
                    ViewBag.Message = "Bạn không có quyền thực hiện thao tác này";
                    ViewBag.ErrorMessage = messageError;
                    return View("Error");
                    // Nếu không, chuyển hướng người dùng đến trang đăng nhập
                }
            }
            catch (Exception)
            {
                // Nếu token không hợp lệ, chuyển hướng người dùng đến trang đăng nhập
                return RedirectToAction("Login", "Auth");
            }
        }



    }
}
