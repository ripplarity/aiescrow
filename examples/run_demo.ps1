# End-to-end demo (PowerShell). --now is a TEST-ONLY clock override.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
function A { & $py -m aiescrow @args; if ($LASTEXITCODE -ne 0) { throw "aiescrow failed: $args" } }
$O = "examples/out"
if (Test-Path $O) { Remove-Item -Recurse -Force $O }
New-Item -ItemType Directory -Force "$O/plain", "$O/keys" | Out-Null

$bytes = New-Object byte[] 1048576
(New-Object Random).NextBytes($bytes)
[IO.File]::WriteAllBytes("$O/plain/adapter.safetensors", $bytes)
[IO.File]::WriteAllText("$O/plain/memories.jsonl", '{"role":"user","text":"remember my cat is called Miso"}')

A keygen vendor --kind ed25519 --out-dir "$O/keys"
A keygen holder --kind ed25519 --out-dir "$O/keys"
A keygen user --kind x25519 --out-dir "$O/keys"

$tpl = '{"depositor":{"name":"ollama-finetune-demo"},"holder":{"name":"demo-holder","type":"local"},"artefact_kinds":{"adapter.safetensors":"fine_tune","memories.jsonl":"memory"},"release_conditions":[{"type":"deadman","params":{"interval_days":90,"grace_days":30}},{"type":"vendor_shutdown"}]}'
[IO.File]::WriteAllText("$O/template.json", $tpl)

A deposit --manifest "$O/template.json" --artefacts "$O/plain" --beneficiary-pub "$O/keys/user.pub" --depositor-key "$O/keys/vendor.key" --out $O --now 2026-01-01T00:00:00Z
A heartbeat --dir $O --depositor-key "$O/keys/vendor.key" --now 2026-02-01T00:00:00Z
A check "$O/manifest.json" --now 2026-03-01T00:00:00Z
A release --dir $O --condition deadman --holder-key "$O/keys/holder.key" --now 2026-06-01T00:00:00Z
A open --dir $O --key "$O/keys/user.key" --out "$O/restored" --now 2026-07-01T00:00:00Z

foreach ($f in "adapter.safetensors", "memories.jsonl") {
  $a = (Get-FileHash "$O/plain/$f").Hash; $b = (Get-FileHash "$O/restored/$f").Hash
  if ($a -ne $b) { throw "HASH MISMATCH $f" }
}
Write-Host "HASH OK (independent Get-FileHash)"

# vendor resumes: a real-clock heartbeat so `aiescrow check` passes without --now
A heartbeat --dir $O --depositor-key "$O/keys/vendor.key"
