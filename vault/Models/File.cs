using System;
using System.Collections.Generic;

namespace vault.Models;

public partial class File
{
    public int Id { get; set; }

    public string Name { get; set; } = null!;

    public byte[] Payload { get; set; } = null!;

    public int UserId { get; set; }

    public virtual User User { get; set; } = null!;
}
