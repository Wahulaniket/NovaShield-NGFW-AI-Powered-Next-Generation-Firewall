param(
    [string]$Gateway = "",
    [int]$TotalRequests = 15000,
    [ValidateSet("login", "health")]
    [string]$Route = "login",
    [ValidateSet("unique", "single")]
    [string]$IpMode = "unique",
    [string]$ClientIp = "198.18.0.60"
)

. "$PSScriptRoot/common.ps1"

Write-Section "Load Test"
$gatewayUrl = Get-GatewayUrl -Gateway $Gateway
Add-Type -AssemblyName System.Net.Http
$loadSource = @"
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

public static class NovaLoadHarness
{
    public static async Task<Dictionary<int, int>> RunAsync(string gatewayUrl, int totalRequests, string route, string ipMode, string clientIp)
    {
        ServicePointManager.DefaultConnectionLimit = Math.Max(ServicePointManager.DefaultConnectionLimit, totalRequests);
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = delegate(HttpRequestMessage request, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors) { return true; };
        var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);

        var tasks = new Task<HttpResponseMessage>[totalRequests];
        for (var i = 0; i < totalRequests; i++)
        {
            var request = new HttpRequestMessage(
                route == "health" ? HttpMethod.Get : HttpMethod.Post,
                route == "health" ? gatewayUrl + "/api/admin/health" : gatewayUrl + "/api/login"
            );

            request.Headers.TryAddWithoutValidation("X-Real-IP", ipMode == "unique" ? "198.18." + (i / 250) + "." + ((i % 250) + 1) : clientIp);

            if (route == "login")
            {
                var json = "{\"username\":\"load-user\",\"password\":\"secret\"}";
                request.Content = new StringContent(json, Encoding.UTF8, "application/json");
            }

            tasks[i] = client.SendAsync(request);
        }

        try
        {
            await Task.WhenAll(tasks);
        }
        catch
        {
        }

        var counts = new Dictionary<int, int>();
        foreach (var task in tasks)
        {
            int code;
            if (task.IsFaulted || task.IsCanceled)
            {
                code = -1;
            }
            else
            {
                code = (int)task.Result.StatusCode;
            }

            if (!counts.ContainsKey(code))
            {
                counts[code] = 0;
            }
            counts[code]++;

            if (task.Status == TaskStatus.RanToCompletion && task.Result != null)
            {
                task.Result.Dispose();
            }
        }

        client.Dispose();
        handler.Dispose();
        return counts;
    }
}
"@

if (-not ("NovaLoadHarness" -as [type])) {
    Add-Type -TypeDefinition $loadSource -Language CSharp -ReferencedAssemblies @("System.dll", "System.Net.Http.dll", "System.Security.dll")
}

$start = Get-Date
$counts = [NovaLoadHarness]::RunAsync($gatewayUrl, $TotalRequests, $Route, $IpMode, $ClientIp).GetAwaiter().GetResult()
$elapsed = (Get-Date) - $start

$summary = [pscustomobject]@{
    total_requests = $TotalRequests
    route = $Route
    ip_mode = $IpMode
    elapsed_seconds = [math]::Round($elapsed.TotalSeconds, 2)
    requests_per_second = if ($elapsed.TotalSeconds -gt 0) { [math]::Round($TotalRequests / $elapsed.TotalSeconds, 2) } else { 0 }
}

$summary | Format-List
Write-Host ""
Write-Host "Status code distribution" -ForegroundColor Cyan
$counts.GetEnumerator() | Sort-Object Key | ForEach-Object {
    Write-Host ("{0} -> {1}" -f $_.Key, $_.Value)
}

$snapshot = Invoke-NovaRequest -Method GET -Uri "$gatewayUrl/api/admin/snapshot"
Show-Result -Label "post-load-snapshot" -Result $snapshot
