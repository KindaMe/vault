using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using vault.Dtos;
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

            return await _context.Credentials.Where(w => w.UserId == userId).ToListAsync();
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

            var credential = await _context.Credentials.FindAsync(id);

            if (credential == null || credential.UserId != userId)
            {
                return NotFound();
            }

            return credential;
        }

        // PUT: api/Credentials/5
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPut("{id}")]
        public async Task<IActionResult> PutCredential(int id, CredentialUpdatedDetailsDto credentialDetails)
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

            credential.Login = credentialDetails.Login;
            credential.Password = credentialDetails.Password;
            credential.App = credentialDetails.App;
            credential.Link = credentialDetails.Link;

            await _context.SaveChangesAsync();

            return CreatedAtAction("GetCredential", new { id = credential.Id }, credential);
        }

        // POST: api/Credentials
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult<Credential>> PostCredential(Credential credential)
        {
            var userIdClaim = User.FindFirst("UserId");

            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out var userId))
            {
                return Unauthorized();
            }

            credential.UserId = userId;

            _context.Credentials.Add(credential);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetCredential", new { id = credential.Id }, credential);
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