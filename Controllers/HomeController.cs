using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using login_registration.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;

namespace login_registration.Controllers
{
    public class HomeController : Controller
    {
        // NOTE DB function
        private login_registrationContext db;
        public HomeController(login_registrationContext context)
        {
            db = context;
        }




        // NOTE routes
        [HttpGet("")]
        public IActionResult Index()
        {
            return View("Index");
        }


        [HttpPost("register")]
        public IActionResult Register(User newUser)
        {
            if (ModelState.IsValid) 
            {
                if (db.Users.Any(u=> u.Email == newUser.Email)) 
                {
                    ModelState.AddModelError("Email", "Email is already in use");
                    return View("Index");
                }
                PasswordHasher<User> Hasher =  new PasswordHasher<User>();
                //Hash the password only after verifying that everything else is good to go
                newUser.Password = Hasher.HashPassword(newUser, newUser.Password);
                db.Add(newUser);
                db.SaveChanges();
                HttpContext.Session.SetInt32("UserId", newUser.UserId);
                return RedirectToAction("Success");
            }
            return View("Index");
        }


        [HttpGet("success")]
        public IActionResult Success()
        {
            if(HttpContext.Session.GetInt32("UserId") == null)
            {
                return RedirectToAction("Index");
            }
            return View("Success");
        }



        [HttpPost("login")]
        public IActionResult Login(LoginUser loginUser)
        {
            if (ModelState.IsValid == false)
            {
                return View("Index");
            }

            User dbUser = db.Users
                .FirstOrDefault(u => u.Email== loginUser.LoginEmail);
            
            if (dbUser == null)
            {
                ModelState.AddModelError("LoginEmail", "Email not found");
            }

            if (ModelState.IsValid == false)
            {
                return View("Index");
            }

            PasswordHasher<LoginUser> hasher = new PasswordHasher<LoginUser>();
            PasswordVerificationResult pwCompareResult = hasher.VerifyHashedPassword(loginUser, dbUser.Password, loginUser.LoginPassword);

            if (pwCompareResult == 0)
            {
                ModelState.AddModelError("LoginEmail", "Incorrect password");
                return View("Index");
            }

            HttpContext.Session.SetInt32("UserId", dbUser.UserId);
            return RedirectToAction("Success");


        }




        // NOTE pre installed things
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [HttpPost("logout")]
        public IActionResult LogOut()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Index");
        }

    }
}
