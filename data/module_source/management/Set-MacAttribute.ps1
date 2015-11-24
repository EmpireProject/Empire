function Set-MacAttribute {
<#
.SYNOPSIS

    Sets the modified, accessed and created (Mac) attributes for a file based on another file or input.

    PowerSploit Function: Set-MacAttribute
    Author: Chris Campbell (@obscuresec)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Version: 1.0.0
 
.DESCRIPTION

    Set-MacAttribute sets one or more Mac attributes and returns the new attribute values of the file.

.EXAMPLE

    PS C:\> Set-MacAttribute -FilePath c:\test\newfile -OldFilePath c:\test\oldfile

.EXAMPLE

    PS C:\> Set-MacAttribute -FilePath c:\demo\test.xt -All "01/03/2006 12:12 pm"

.EXAMPLE

    PS C:\> Set-MacAttribute -FilePath c:\demo\test.txt -Modified "01/03/2006 12:12 pm" -Accessed "01/03/2006 12:11 pm" -Created "01/03/2006 12:10 pm"

.LINK
    
    http://www.obscuresec.com/2014/05/touch.html
  
#>
    [CmdletBinding(DefaultParameterSetName = 'Touch')] 
        Param (
    
        [Parameter(Position = 1,Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FilePath,
    
        [Parameter(ParameterSetName = 'Touch')]
        [ValidateNotNullOrEmpty()]
        [String]
        $OldFilePath,
    
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Modified,

        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Accessed,

        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Created,
    
        [Parameter(ParameterSetName = 'All')]
        [DateTime]
        $AllMacAttributes
    )

    Set-StrictMode -Version 2.0
    
    #Helper function that returns an object with the MAC attributes of a file.
    function Get-MacAttribute {
    
        param($OldFileName)
        
        if (!(Test-Path $OldFileName)){Throw "File Not Found"}
        $FileInfoObject = (Get-Item $OldFileName)

        $ObjectProperties = @{'Modified' = ($FileInfoObject.LastWriteTime);
                              'Accessed' = ($FileInfoObject.LastAccessTime);
                              'Created' = ($FileInfoObject.CreationTime)};
        $ResultObject = New-Object -TypeName PSObject -Property $ObjectProperties
        Return $ResultObject
    } 
    
    #test and set variables
    if (!(Test-Path $FilePath)){Throw "$FilePath not found"}

    $FileInfoObject = (Get-Item $FilePath)
    
    if ($PSBoundParameters['AllMacAttributes']){
        $Modified = $AllMacAttributes
        $Accessed = $AllMacAttributes
        $Created = $AllMacAttributes
    }

    if ($PSBoundParameters['OldFilePath']){

        if (!(Test-Path $OldFilePath)){Write-Error "$OldFilePath not found."}

        $CopyFileMac = (Get-MacAttribute $OldFilePath)
        $Modified = $CopyFileMac.Modified
        $Accessed = $CopyFileMac.Accessed
        $Created = $CopyFileMac.Created
    }

    if ($Modified) {$FileInfoObject.LastWriteTime = $Modified}
    if ($Accessed) {$FileInfoObject.LastAccessTime = $Accessed}
    if ($Created) {$FileInfoObject.CreationTime = $Created}

    Return (Get-MacAttribute $FilePath)
}
