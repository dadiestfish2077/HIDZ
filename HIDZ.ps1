# Check if PowerShell is running as an administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run PowerShell as an administrator."
    Exit
}

$SMTPServer = "smtp.gmail.com"
$SMTPPort = 587
$From = "youremail@gmail.com"
$To = "youremail2@gmail.com"
$Subject = "Suspicious Activity Alert"
$AppPassword = "gmail_app_password"

$Credential = New-Object System.Management.Automation.PSCredential($From, (ConvertTo-SecureString -String $AppPassword -AsPlainText -Force))

$EventIDs = 1102, 4672, 4670, 4907, 4719, 602, 4950

$check_time = [DateTime]::MinValue

while ($true) {
    # Get events from the Security event log
    $events = Get-WinEvent -FilterHashTable @{Logname = 'Security'; ID = $EventIDs}

    $sortedEvents = $events | Sort-Object TimeCreated

    $latestEvent = $sortedEvents[-1]

    $lastEventTime = $latestEvent.TimeCreated

    while ($lastEventTime -gt $check_time) {
        foreach ($event in $sortedEvents) {
            Write-Host "Event ID: $($event.Id)"
            Write-Host $event.Message

            $check_time = $event.TimeCreated

            Write-Host $check_time

            Write-Host "This is the last event time: $lastEventTime"

            # Build the email body
            $Body = @"
Event ID: $($event.Id)
Message: $($event.Message)
Time Created: $($event.TimeCreated)
"@

            # Send email
            Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body -SmtpServer $SMTPServer -Port $SMTPPort -Credential $Credential -UseSsl
        }
    }
}