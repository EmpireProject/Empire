function Find-TrustedDocuments
{
<#
.SYNOPSIS

This script is used to get useful information from a computer.

Function: Enumerate-TrustedDocuments
Author: Jeff McCutchan, Twitter: @jamcut
Required Dependencies: None
Optional Dependencies: None
Version: 0.1

.DESCRIPTION

This script is used to enumerate trusted documents and trusted locations for Micorsoft Office. Currently, the script only supports Excel enumeration.

.EXAMPLE

Enumerate-TrustedDocuments
Enumerates trusted documentd and trusted locations from the registry.

.NOTES
This script is useful for identifying which documents have been trusted by the user already.  The attacker can manually download the document and modify the macro.
When uploaded to the original locations (thus overwriting the original document) the modified macro will continue to execute without prompting the user.

.LINK
https://github.com/jamcut/one-offs/blob/master/Find-TrustedDocuments.ps1

#>
    $BASE_EXCEL_REG_LOCATIONS = "HKCU:\Software\Microsoft\Office\11.0\Excel\Security", "HKCU:\Software\Microsoft\Office\12.0\Excel\Security", "HKCU:\Software\Microsoft\Office\14.0\Excel\Security", "HKCU:\Software\Microsoft\Office\15.0\Excel\Security" 

    $verified_excel_base_reg_locations = @()
    $trusted_excel_documents = @()

    # Verify registry locations for Excel exist
    foreach ($location in $BASE_EXCEL_REG_LOCATIONS){
        $valid_path = Test-Path $location
        if ($valid_path -eq $True){
            $verified_excel_base_reg_locations += $location
        }
    }
    if ($verified_excel_base_reg_locations.length -eq 0){
        Write-Output "[*] No trusted document locations found"
    }
    else {
        Write-Output "[+] Trusted Document Locations for Excel"
        # String manipulation to create and print the full path for each trusted location
        foreach ($base_excel_reg_location in $verified_excel_base_reg_locations){
            $trusted_location_root = $base_excel_reg_location + "\Trusted Locations"
            $all_trusted_locations = (Get-ChildItem $trusted_location_root) | Select Name
            foreach ($loc in $all_trusted_locations){
                $complete_reg_path = $trusted_location_root + "\" + ($loc.Name | Split-Path -leaf)
                $location_props = Get-ItemProperty $complete_reg_path
                $path = $location_props.Path
                Write-Output $path
            }
        }
    }
    # Enumerate registry to identify documents that have previously been trusted
    foreach ($valid_location in $verified_excel_base_reg_locations){
        $valid_location = $valid_location + "\Trusted Documents"
        if ((Test-Path $valid_location) -eq $True){
            $trusted_document_property = Get-ChildItem $valid_location | select Property
            $trusted_document = [System.Environment]::ExpandEnvironmentVariables($trusted_document_property.property)
            $trusted_excel_documents += $trusted_document
        }
    }
    if ($trusted_excel_documents.length -eq 0){
        Write-Output "`n[*] No trusted documents found"
    }
    else{
        Write-Output "`n[+] Trusted documents:"
        foreach ($doc in $trusted_excel_documents){
            Write-Output $doc"`n"
    }
    }
    Write-Output "`n"
}