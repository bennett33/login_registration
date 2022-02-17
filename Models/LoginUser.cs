using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace login_registration.Models
{
    [NotMapped]
    public class LoginUser
    {

        [Required(ErrorMessage = "is required")]
        [EmailAddress]
        [Display(Name = "Email")]
        public string LoginEmail { get; set; }


        [Required(ErrorMessage = "is required")]
        [MinLength(8,ErrorMessage = "must be at least 8 characters")]
        [Display(Name = "Password")]
        [DataType(DataType.Password)]
        public string LoginPassword { get; set; }
    }
}
