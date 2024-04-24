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
    public class FilesController : ControllerBase
    {
        private readonly VaultContext _context;

        public FilesController(VaultContext context)
        {
            _context = context;
        }

        // GET: api/Files
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Models.File>>> GetFiles()
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

            var files = await _context.Files.Where(x => x.UserId == userId).ToListAsync();

            foreach (var file in files)
            {
                file.Payload = Convert.FromBase64String(
                    SecurityMagician.DecryptPassword(Convert.ToBase64String(file.Payload), file.Name,
                        userKeyClaim.Value));
            }

            return files;
        }

        // GET: api/Files/5
        [HttpGet("{id}")]
        public async Task<ActionResult<Models.File>> GetFile(int id)
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

            var @file = await _context.Files.FindAsync(id);

            if (@file == null || @file.UserId != userId)
            {
                return NotFound();
            }

            @file.Payload =
                Convert.FromBase64String(SecurityMagician.DecryptPassword(Convert.ToBase64String(@file.Payload),
                    @file.Name, userKeyClaim.Value));

            return @file;
        }

        // POST: api/Files
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult<Models.File>> PostFile(UserFilesDTO file)
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

            if (string.IsNullOrEmpty(file.Name) || file.Payload == null)
            {
                return BadRequest("Invalid file data");
            }

            var encryptedPayload =
                SecurityMagician.EncryptPassword(Convert.ToBase64String(file.Payload), file.Name, userKeyClaim.Value);

            Models.File newFile = new Models.File
            {
                Name = file.Name,
                Payload = Convert.FromBase64String(encryptedPayload),
                UserId = userId
            };

            _context.Files.Add(newFile);
            await _context.SaveChangesAsync();
            
            var returnFile = new 
            {
                newFile.Id,
                newFile.Name,
                file.Payload
            };

            return CreatedAtAction("GetFile", new { id = newFile.Id }, returnFile);
        }

        // DELETE: api/Files/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteFile(int id)
        {
            var userIdClaim = User.FindFirst("UserId");

            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out var userId))
            {
                return Unauthorized();
            }

            var @file = await _context.Files.FindAsync(id);
            if (@file == null || @file.UserId != userId)
            {
                return NotFound();
            }

            _context.Files.Remove(@file);
            await _context.SaveChangesAsync();

            return NoContent();
        }
    }
}