using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace login_registration.Models
{
    public class User
    {
        [Key] // the below prop is the primary key, [Key] is not needed if named with pattern: ModelNameId
        public int UserId { get; set; }


        [Required(ErrorMessage = "is required")]
        [MinLength(2, ErrorMessage = "must be at least 2 characters")]
        [Display(Name = "First Name")]
        public string FirstName { get; set; }
        

        [Required(ErrorMessage = "is required")]
        [MinLength(2, ErrorMessage = "must be at least 2 characters")]
        [Display(Name = "Last Name")]
        public string LastName { get; set; }


        [Required(ErrorMessage = "is required")]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }


        [Required(ErrorMessage = "is required")]
        [MinLength(8,ErrorMessage = "must be at least 8 characters")]
        [Display(Name = "Password")]
        [DataType(DataType.Password)]
        public string Password { get; set; }


        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime UpdatedAt { get; set; } = DateTime.Now;

        [NotMapped]
        [Compare("Password")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; }
    }
}
