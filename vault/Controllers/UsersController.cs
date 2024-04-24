using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using vault.Dtos;
using vault.Models;
using vault.Helpers;

namespace vault.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly Regex _emailRegex = new Regex(@"^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$");

        private readonly VaultContext _context;

        public UsersController(VaultContext context)
        {
            _context = context;
        }

        // GET: api/Users
        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetUserDetails()
        {
            // Get the user ID from the token
            var userIdClaim = User.FindFirst("UserId");

            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out var userId))
            {
                return Unauthorized();
            }

            // Retrieve wallets based on the user ID
            var user = await _context.Users.FindAsync(userId);

            if (user != null && user.IsActive == 1)
            {
                user.Password = new string('*', user.Password.Length);
                return user;
            }
            else
            {
                return NotFound();
            }
        }

        // POST: api/Users
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult<User>> PostUser(UserCredentialsDTO user)
        {
            if (user.Email.IsNullOrEmpty() || user.Password.IsNullOrEmpty())
            {
                return BadRequest("Invalid credentials");
            }

            if (!_emailRegex.IsMatch(user.Email))
            {
                return BadRequest(new { message = "Email is not in correct format" });
            }

            bool emailExists = await _context.Users.AnyAsync(u => u.Email == user.Email);
            if (emailExists)
            {
                return Conflict("Email already in use");
            }

            var key = SecurityMagician.GenerateEncryptionKey();
            var keyString = Convert.ToBase64String(key);

            User newUser = new User
            {
                Email = user.Email,
                Password = SecurityMagician.HashPassword(user.Password, user.Email)
            };

            _context.Users.Add(newUser);

            await _context.SaveChangesAsync();

            return Created("", new { Key = keyString });
        }
    }
}