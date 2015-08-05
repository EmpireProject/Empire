Function Invoke-Thunderstruck
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $False, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $VideoURL = "https://www.youtube.com/watch?v=leJ_wj7mDa0"
    )
    
    Function Set-Speaker($Volume){$wshShell = new-object -com wscript.shell;1..50 | % {$wshShell.SendKeys([char]174)};1..$Volume | % {$wshShell.SendKeys([char]175)}}
    Set-Speaker -Volume 50   

    #Create hidden IE Com Object
    $IEComObject = New-Object -com "InternetExplorer.Application"
    $IEComObject.visible = $False
    $IEComObject.navigate($VideoURL)

    Start-Sleep -s 5

    $EndTime = (Get-Date).addseconds(90)

    # ghetto way to do this but it basically presses volume up to raise volume in a loop for 90 seconds
    do {
       $WscriptObject = New-Object -com wscript.shell
       $WscriptObject.SendKeys([char]175)
    }
    until ((Get-Date) -gt $EndTime)
}