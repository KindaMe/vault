using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using vault.Dtos;
using vault.Helpers;
using vault.Models;

namespace vault.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class CredentialsController : ControllerBase
    {
        private readonly VaultContext _context;

        public CredentialsController(VaultContext context)
        {
            _context = context;
        }

        // GET: api/Credentials
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Credential>>> GetCredentials()
        {
            var userIdClaim = User.FindFirst("UserId");

            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out var userId))
            {
                return Unauthorized();
            }

            var userKeyClaim = User.FindFirst("Key");
            if (userKeyClaim == null)
            {
                return Unauthorized();
            }

            var credentials = await _context.Credentials.Where(w => w.UserId == userId).ToListAsync();

            foreach (var credential in credentials)
            {
                credential.Password =
                    SecurityMagician.DecryptPassword(credential.Password, credential.App, userKeyClaim.Value);
            }

            return credentials;
        }

        // GET: api/Credentials/5
        [HttpGet("{id}")]
        public async Task<ActionResult<Credential>> GetCredential(int id)
        {
            var userIdClaim = User.FindFirst("UserId");

            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out var userId))
            {
                return Unauthorized();
            }

            var userKeyClaim = User.FindFirst("Key");
            if (userKeyClaim == null)
            {
                return Unauthorized();
            }
            
            var credential = await _context.Credentials.FindAsync(id);

            if (credential == null || credential.UserId != userId)
            {
                return NotFound();
            }

            credential.Password =
                SecurityMagician.DecryptPassword(credential.Password, credential.App, userKeyClaim.Value);

            return credential;
        }


        // POST: api/Credentials
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult<Credential>> PostCredential(CredentialUpdatedDetailsDto credential)
        {
            var userIdClaim = User.FindFirst("UserId");

            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out var userId))
            {
                return Unauthorized();
            }

            var userKeyClaim = User.FindFirst("Key");
            if (userKeyClaim == null)
            {
                return Unauthorized();
            }

            var userKey = Convert.FromBase64String(userKeyClaim.Value);

            var iv = SecurityMagician.StringToIV(credential.App);
            var encryptedPassword = SecurityMagician.EncryptPassword(credential.Password, iv, userKey);

            var newCredential = new Credential
            {
                Login = credential.Login,
                Password = encryptedPassword,
                App = credential.App,
                Link = credential.Link,
                UserId = userId
            };

            _context.Credentials.Add(newCredential);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetCredential", new { id = newCredential.Id }, credential);
        }

        // DELETE: api/Credentials/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteCredential(int id)
        {
            var userIdClaim = User.FindFirst("UserId");

            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out var userId))
            {
                return Unauthorized();
            }

            var credential = await _context.Credentials.FindAsync(id);

            if (credential == null || credential.UserId != userId)
            {
                return NotFound();
            }

            _context.Credentials.Remove(credential);
            await _context.SaveChangesAsync();

            return NoContent();
        }
    }
}