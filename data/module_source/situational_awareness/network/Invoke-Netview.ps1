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

            $CompSearcher.FindAll() | ForEach-Object {
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


# expose the Win32API functions and datastructures below
# using PSReflect

$Mod = New-InMemoryModule -ModuleName Win32

# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([string], [string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func kernel32 GetLastError ([Int]) @())
)

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

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
$Kernel32 = $Types['kernel32']
