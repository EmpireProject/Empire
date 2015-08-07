Function Invoke-VoiceTroll
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $VoiceText
    )
    Set-StrictMode -version 2
  Add-Type -AssemblyName System.Speech
  $synth = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
  $synth.Speak($VoiceText)
}
