# Move old project folders into ./archive to keep workspace clean
$paths = @(
    "Projeto",
    "PBD_Projeto",
    "Projeto\venv",
    "PBD_Projeto\venv",
    "venv",
    "Projeto/db.sqlite3",
    "PBD_Projeto/db.sqlite3"
)
$archive = Join-Path -Path (Get-Location) -ChildPath "archive"
if (-not (Test-Path $archive)) { New-Item -ItemType Directory -Path $archive | Out-Null }

foreach ($p in $paths) {
    if (Test-Path $p) {
        $leaf = Split-Path $p -Leaf
        $dest = Join-Path $archive $leaf
        $unique = $dest
        $i = 1
        while (Test-Path $unique) {
            $unique = "${dest}-$i"
            $i++
        }
        Write-Output "Moving '$p' -> '$unique'"
        try {
            Move-Item -Path $p -Destination $unique -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to move $p"
            Write-Warning $_.Exception.Message
        }
    } else {
        Write-Output "Not found: $p"
    }
}

Write-Output "Archive complete. Review ./archive to confirm files."