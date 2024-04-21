using System;
using System.Collections.Generic;

namespace vault.Models;

public partial class User
{
    public int Id { get; set; }

    public string Email { get; set; } = null!;

    public string Password { get; set; } = null!;

    public byte? IsActive { get; set; }

    public virtual ICollection<Credential> Credentials { get; set; } = new List<Credential>();

    public virtual ICollection<File> Files { get; set; } = new List<File>();
}
