# FortressAuth IT113 - read-only hosted deployment diagnostics
# No credentials, no POST, no database changes, no ML inference requests.
# Review the URLs before running. The defaults were found in earlier project configuration.
param(
    [string]$VercelUrl = 'https://tank-web-kk6z.vercel.app',
    [string]$PhpRenderUrl = 'https://tankweb-v3.onrender.com',
    [string]$MlHealthUrl = ''
)

$ErrorActionPreference = 'Stop'
$checks = New-Object 'System.Collections.Generic.List[object]'

function Invoke-ReadOnlyProbe {
    param(
        [string]$Name,
        [string]$Url,
        [int[]]$Accept,
        [string]$Marker = '',
        [string]$ExpectedType = ''
    )
    $code = 0
    $content = ''
    $contentType = ''
    $note = ''
    try {
        $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 45 -MaximumRedirection 3 -UseBasicParsing -Headers @{ 'Accept' = '*/*' }
        $code = [int]$response.StatusCode
        $content = [string]$response.Content
        $contentType = [string]$response.Headers['Content-Type']
    }
    catch {
        $ex = $_.Exception
        if ($null -ne $ex.Response) {
            try {
                $code = [int]$ex.Response.StatusCode
                $contentType = [string]$ex.Response.ContentType
                $stream = $ex.Response.GetResponseStream()
                if ($null -ne $stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $content = $reader.ReadToEnd()
                    $reader.Dispose()
                }
            } catch { $note = 'Unable to read HTTP error status' }
        } else {
            $note = 'Connection or TLS error (check deployment and URL)'
        }
    }
    $pass = $Accept -contains $code
    if ($pass -and $Marker -ne '' -and -not $content.Contains($Marker)) { $pass = $false; $note = 'Unexpected response content' }
    if ($pass -and $ExpectedType -ne '' -and -not $contentType.ToLowerInvariant().Contains($ExpectedType)) {
        $pass = $false; $note = 'Unexpected Content-Type'
    }
    $state = if ($pass) { 'PASS' } else { 'CHECK' }
    $checks.Add([pscustomobject]@{ Test = $Name; Result = $state; HTTP = $code; Notes = $note })
    Write-Host ("[{0}] {1}: HTTP {2} {3}" -f $state, $Name, $code, $note)
}

$VercelUrl = $VercelUrl.TrimEnd('/')
$PhpRenderUrl = $PhpRenderUrl.TrimEnd('/')
Write-Host 'FortressAuth - Hosted Read-Only Verification' -ForegroundColor Cyan
Write-Host "Frontend: $VercelUrl"
Write-Host "PHP backend: $PhpRenderUrl"
Write-Host 'These GET probes never run model predictions or write database records.'

Invoke-ReadOnlyProbe 'Vercel academic dashboard' "$VercelUrl/assessment/" @(200) 'FortressAuth'
Invoke-ReadOnlyProbe 'Vercel current dashboard JS' "$VercelUrl/assessment/it113-live.js" @(200)
Invoke-ReadOnlyProbe 'Vercel model metadata' "$VercelUrl/assessment/model_summary.json" @(200) 'dataset'
Invoke-ReadOnlyProbe 'Vercel evaluation PDF' "$VercelUrl/assessment/it113_model_evaluation.pdf" @(200) '' 'pdf'
Invoke-ReadOnlyProbe 'Render PHP route exists (GET rejected by design)' "$PhpRenderUrl/it113_demo_infer.php" @(405)
Invoke-ReadOnlyProbe 'Vercel PHP reverse proxy (GET rejected by design)' "$VercelUrl/it113_demo_infer.php" @(405)
Invoke-ReadOnlyProbe 'Vercel session-history endpoint' "$VercelUrl/it113_demo_history.php" @(200,503)
if ($MlHealthUrl.Trim() -ne '') {
    Invoke-ReadOnlyProbe 'Optional ML health endpoint' $MlHealthUrl @(200) 'ok'
}
Write-Host ''
$checks | Format-Table -AutoSize
Write-Host 'Note: HTTP 503 on session history can mean the public demo is intentionally disabled.'
Write-Host 'Never submit your ML_SERVICE_TOKEN, DB_PASS, or .env file to a public form or chat.'
