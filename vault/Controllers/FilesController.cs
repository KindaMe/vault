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

            return await _context.Files.Where(x => x.UserId == userId).ToListAsync();
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

            var @file = await _context.Files.FindAsync(id);

            if (@file == null || @file.UserId != userId)
            {
                return NotFound();
            }

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

            if (file == null || string.IsNullOrEmpty(file.Name) || file.Payload == null)
            {
                return BadRequest("Invalid file data");
            }

            Models.File newFile = new Models.File
            {
                Name = file.Name,
                Payload = file.Payload,
                UserId = userId
            };

            _context.Files.Add(newFile);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetFile", new { id = newFile.Id }, newFile);
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