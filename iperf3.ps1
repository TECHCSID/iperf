# Script récupérant les vitesses de connexion en Upload, Download et la valeur de la latence, aléatoirement du lundi au dimanche et de 9h à 18h.
# iperf.genapicloud.com 10.19.66.79
# Le tout est inscrit dans le registre à la clé HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf\
# V2 06/01/2022 - Modifié par Arnaud BASTIDE  : Implémentation du reverse Mode -R pour tester le downlad, l'ancienne version était érronnée. Changement de répertoire de travail.
# V3 10/01/2022 - Modifié par Arnaud BASTIDE  : Ajout Bypass du contrôle de plannification " .ps1 -Bypass"
# V4 15/04/2022 - Modifié par Arnaud BASTIDE  : Test Plage IP REAL n'est plus valide et a été enlevé, amélioration ajout serveur Iperf externe et lecture Json


Param (
    [Parameter(Mandatory=$false)] [switch]$Bypass = $false
)

Function Write-Log
{
	param (
        [Parameter(Mandatory=$True)]
        [array]$LogOutput
	)
    
    if ( !$(Test-Path $LogFile)) { New-Item -ItemType "file" -path $LogFile -Force }
	$currentDate = (Get-Date -UFormat "%d-%m-%Y")
	$currentTime = (Get-Date -UFormat "%T")
	$logOutput = $logOutput -join (" ")

    #Add-content -path $PathFile -value "[$currentDate $currentTime] $logOutput"

	"[$currentDate $currentTime] -  $logOutput" | Out-File $LogFile -Append

}

# try{
# something right!
# }
# Catch{
# write-log -LogOutput ("Failed to do something right:  {0}" -f $_) -Path $LogFile
# }

   function TestVersionPowershell {
     try {
         $tmp = '{test:1}' | ConvertFrom-Json
         $global:powershell30=$True
         #LogWrite("Powershell version should be >= 30");
      }
      catch {
         $global:powershell30=$False
         #LogWrite("Powershell version should be < 30");
      } 
      finally {
         $global:PSVersionMajor = $PSVersionTable.PSVersion.Major
      } 

   }# fin Fonction
  
  function ConvertFrom-Json20([object] $item){ 
        add-type -assembly system.web.extensions
        $ps_js=new-object system.web.script.serialization.javascriptSerializer

        #The comma operator is the array construction operator in PowerShell
        return ,$ps_js.DeserializeObject($item)
  }

  function Get-JsonContent {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [ValidateScript({
                if(-Not ($_ | Test-Path) ){
                    throw "Le fichier transmis est introuvable !"
                }
                if(-Not ($_ | Test-Path -PathType Leaf) ){
                    throw "L'argument transmis n'est pas un fichier !"
                }
                if($_ -notmatch "(\.json)"){
                    throw "Le fichier transmis n'est pas un fichier JSON !"
                }
                return $true 
            })]
            [System.IO.FileInfo]$File
        )
    
        if ( $global:powershell30 ) {
            [Array]$JsonFile   =  Get-Content $File -Raw | ConvertFrom-Json
        }
        if ($global:powershell30 -eq $false) {
           if ($global:PSVersionMajor -eq 2 ) {  [Array]$JsonFile   =  ConvertFrom-Json20 ( [System.IO.File]::ReadAllText($File) )     }
           else { [Array]$JsonFile   =  ConvertFrom-Json20 ( $(Get-Content $File -Raw) ) }
           
           #
        }         

        return $JsonFile
    }


# --------- Fonction IPerf ---------
	function iperf_start 
	{
        param (
            [Parameter(Mandatory=$True)]
            [string]$iperf_serveur,
            [Parameter(Mandatory=$True)]
            [string]$iperf_port,
            [Parameter(Mandatory=$False)]
            [bool]$Reverse=$false
	    )

        $DurationTest = 20
        $wait = $DurationTest + 4
        $Interval = 3
	    
        $IperfParam = "-c $iperf_serveur -p $iperf_port -f m -i $Interval -t $DurationTest -J"
        if ($Reverse)
        { $IperfParam += " -R" }

        #$iperf_cmd = "/c "+$WorkingDir+"iperf3.exe -c $iperf_serveur -p $iperf_port -f m -i $Interval -t $DurationTest -J > "+$json_fullpath
        #$iperf_cmd = "/c "+$WorkingDir+"iperf3.exe $IperfParam"+" > "+$json_fullpath
        $iperf_cmd = "/c iperf3.exe $IperfParam"+" > "+$json_fullpath

        
	    $iperf_cmd = "`""+$iperf_cmd+"`""
	    Write-Log -LogOutput $(" "+$iperf_cmd)

	    $process = start-process -FilePath $NomExe -ArgumentList $iperf_cmd -workingdirectory $archive_fullpath -WindowStyle hidden 
	    start-sleep $wait
	    kill_iperf #Au cas ou il n'est pas terminé
	    Start-Sleep 2
        
        $iperfresult = iperf_result -json $json_fullpath
	    return $iperfresult
	}


# --------- Fonction IPerf Result ---------
    Function iperf_result 
    {
        param (
            [Parameter(Mandatory=$True)]
            [string]$json 
	    )
        
        $Global:ErroriPerf =$null
        if ([System.IO.File]::Exists($json)) 
        {
            #$result = Invoke-WebRequest -UseBasicParsing $json | ConvertFrom-Json
            $result =  Get-JsonContent -File $json
            if ( ($null -eq $result) -or $( $null -eq $($result.end).sum_received) )
            {
               $speed = $null
               $Global:ErroriPerf =  $result.error
             }
            else {
                $speed = [math]::round((((($result.end).sum_received).bits_per_second) / "1MB"),1)
            }
        }
        else {
            $speed = $null
        }
        
        #return "DOWN:$downloadspeed;UP:$uploadspeed"
        return $speed
    }



# --------- Fonction kill_cmd_iperf ---------
 Function kill_cmd_iperf
    {
        $process = "cmd.exe"
        $processus_cmd = ((Get-WmiObject Win32_Process -Filter "name = '$process'") | Select-Object CommandLine, ProcessId) 
        foreach ($process_cmd in $processus_cmd)
        {
            if ($process_cmd.CommandLine -like "*iperf*") {    
               stop-process -Id $process_cmd.ProcessId -Force
            }
        }
  }

# --------- Fonction kill_iperf ---------
 Function kill_iperf
    {
        $process = "iperf3.exe"
        $processus_cmd = ((Get-WmiObject Win32_Process -Filter "name = '$process'") | Select-Object CommandLine, ProcessId) 
        foreach ($process_cmd in $processus_cmd)
        {
            if ($process_cmd.CommandLine -like "*iperf*") {    
               stop-process -Id $process_cmd.ProcessId -Force
            }
        }
  }


#-------------- Fonction Set-Day -----------#
function Set-day
    {
        $day_number = Get-Random -Minimum 0 -Maximum 6
        return $day_number
    }

# --------- Fin de fonction Set-Hour ---------
function Set-Hour
    {
        $Hour_num = Get-Random -Minimum $MinHourExecution -Maximum $MaxHourExecution
        return $Hour_num
    }



function CheckForExecution
{
    
    # Teste si le serveur est physique, si non Exit -----------------------------------------------------------
    $Srv_type = Get-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -ErrorAction Ignore
    if ($Srv_type) {
	   Exit
    }

    
    $check_lastYear = Get-Itemproperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "LastYear" -ErrorAction Ignore
    if (!$check_lastYear){
       New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "LastYear" -PropertyType String -Force > $null
    }

    
    #Gestion dernier test realisé est très ancien
    if ( $Year -ne $check_lastYear.LastYear ){
        remove-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Day_number"  -ErrorAction Ignore
        remove-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Hour_number"  -ErrorAction Ignore
        New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Lastweek" -PropertyType String -Force > $null 
    }
    
    if ( $($thisweek - $check_lastweek.lastweek) -ge 3) {
        remove-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Day_number"  -ErrorAction Ignore
        remove-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Hour_number"  -ErrorAction Ignore
        New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Lastweek" -PropertyType String -Force > $null 
    }


    $check_lastweek = Get-Itemproperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Lastweek" -ErrorAction Ignore
    if (!$check_lastweek){
       New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Lastweek" -PropertyType String -Force > $null 
    }elseif ($check_lastweek.lastweek -eq $thisweek ){
       Exit
    }


    # --------- Création d'un jour d'execution aléatoir
    $Day_Number = Get-Itemproperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Day_number"  -ErrorAction Ignore
    $Day_Number = $Day_Number.Day_number
    if (  $($Day_Number -eq $null -or !$Day_Number -or $Day_Number -eq "")   ) {
       $Day_Number = set-day
       New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Day_number" -PropertyType String -Value $Day_Number -Force > $null  
    }

    # --------- Création d'une heure d'execution aléatoire
    $Hour_Number = Get-Itemproperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Hour_number"  -ErrorAction Ignore
    $Hour_Number = $Hour_Number.Hour_number
    if (  $($Hour_Number -eq $null -or !$Hour_Number -or $Hour_Number -eq "")  ) {
       $Hour_Number = Set-Hour
       New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Hour_number" -PropertyType String -Value $Hour_Number -Force > $null 
    }

    #Si on n'est pas dans le bon jour, on sort
    if ( $($Today -ne $Day_Number) ) {
       exit
    }

    #Dans le cas d'une programmation à 17h, execution possible entre 18h et 19h
    #Fréquence execution du scipt RG est programmé toute les 2 heures
    if ($Hour_Number -eq 17)
    {
        $MaxHourExecution += 1       
    }

    # Si on n'est pas dans la bonne plage horaire pour démarrer, on sort
    if (  $($Hour -lt $MinHourExecution -or $Hour -ge $MaxHourExecution)   ) {
       exit
    }

    #Check si on est sur la bonne heure (+ marge d'une heure)
    #Fréquence execution du scipt RG est programmé toute les 2 heures
    if (  !$(  ($Hour -ge $Hour_Number) -and ($Hour -lt $($Hour_Number+2)) )  )
    {
       exit
    }


#Fin CheckExecution
} 

Function GetCurrentIperfExt_Settings_Srv_Port {
 $Serv = $Global:iPerfServersExterneSettings | Where-Object { $_.Id -eq $Global:CurrentiPerfServersExterneSettings.Id } | Select-Object -ExpandProperty Server
 $prt   = $Global:CurrentiPerfServersExterneSettings.Port
 return $Serv,$prt
}

Function UpdateCurrentIperfExt_Settings {

    if ( 0 -eq $Global:CurrentiPerfServersExterneSettings.Id ) {
        $Global:CurrentiPerfServersExterneSettings.Id = 1
        $Global:CurrentiPerfServersExterneSettings.Port = $Global:iPerfServersExterneSettings | Where-Object { $_.Id -eq $Global:CurrentiPerfServersExterneSettings.Id } | Select-Object -ExpandProperty StartPort
    }
    else {

        if ( $Global:CurrentiPerfServersExterneSettings.Port -lt ($Global:iPerfServersExterneSettings | Where-Object { $_.Id -eq $Global:CurrentiPerfServersExterneSettings.Id } | Select-Object -ExpandProperty EndPort) ) {
            # Dans ce cas, il faut juste incrémenter le port
            $Global:CurrentiPerfServersExterneSettings.Port += 1
        }
        else {
            # cas ou port a atteint la limite EndPort, on passe au serveur suivant

            #Test si on 
            if (  ($Global:iPerfServersExterneSettings | Select-Object -ExpandProperty Id)  -contains ($Global:CurrentiPerfServersExterneSettings.Id + 1)  ) {
                $Global:CurrentiPerfServersExterneSettings.Id += 1
                $Global:CurrentiPerfServersExterneSettings.Port = $Global:iPerfServersExterneSettings | Where-Object { $_.Id -eq $Global:CurrentiPerfServersExterneSettings.Id } | Select-Object -ExpandProperty StartPort
            }
            else {
                $Global:CurrentiPerfServersExterneSettings = @{Id = $null ; Port = $null  }
            }
          
        }# Fin Else
        

    # Fin Else
    }

}#Fin fonction


# --------- Initialisation de variables du script ---------
#Indispensable pour Invoke-WebRequest -UseBasicParsing avec RG sur le Host ($progressPreference = "silentlyContinue")
$Global:ErroriPerf =$null
$progressPreference = "silentlyContinue"
$iperfresult = $null
$Now = Get-Date
#$date_now = Get-Date
$NomExe = "C:\Windows\System32\cmd.exe"

$archive_name = "iperf-3.1.3-win64.zip"  # /!\/!\/!\/!\/!\/!\/!\ =====> Modifier ici le nom du fichier à télécharger si mise à jour <===== /!\/!\/!\/!\/!\/!\/!\ 
$zip_source = "http://deploiement-rg.septeocloud.com/$archive_name"
$archivefolder_name = [System.IO.Path]::GetFileNameWithoutExtension($archive_name)

#WorkingDir
#$ScriptName = [io.path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$ScriptName = "iperf3"


$WorkingFolder = "$($env:ProgramData)\Septeo\Supervision"
$WorkingDir = $($WorkingFolder+"\"+$ScriptName+"\")
$archive_fullpath = $WorkingDir+$archivefolder_name+"\"
$scripts_folder = $WorkingDir

$LocalPathArchiveIperf= $WorkingDir+$archive_name  

$json_fullpath = $archive_fullpath+"result.json"

#Creating logoutput and filenames
$LogFolder = $WorkingDir+"Logs"
$LogFile = $LogFolder + "\" + $ScriptName + "-" + (Get-Date -UFormat "%d-%m-%Y") + ".log"

#Plannif condition execution
#Custom script est configuré sur une fréquence de 2h
$MinHourExecution=9
$MaxHourExecution=18

# Teste si il a déjà tourné cette semaine si oui Exit
$thisweek = Get-Date -UFormat %W
$Today = $Now.DayOfWeek.value__ #0 = Dimanche, 1 = Lundi ...
$Hour = $Now.Hour
$Year = $Now.Year

# Créatrion des clef:
$check_reg_Septeo = Get-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\" -ErrorAction Ignore
if (!$check_reg_Septeo){ New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\" }

$check_regkey = Get-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\" -ErrorAction Ignore
   if (!$check_regkey)  { New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision" }
New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -ErrorAction Ignore


if ( !$Bypass -or ($null -eq $Bypass) ) 
{
    CheckForExecution

    #Dans ce cas, nous sommes sur le bon jour, et tranche horaire déterminé. Si Une erreur venait à se produire, suppression des clé pour regenérer une nouvelle plannfication à la prochaine execution
    remove-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Day_number"  -ErrorAction Ignore
    remove-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Hour_number"  -ErrorAction Ignore
    remove-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Lastweek"  -ErrorAction Ignore
    remove-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "LastYear"  -ErrorAction Ignore
    
}

#Test version pour gestion Json
TestVersionPowershell

# Write-Output "Test répertoire $WorkingFolder : $(Test-Path $WorkingFolder -PathType Container)"
if (!(Test-Path $WorkingFolder -PathType Container))  { New-Item -ItemType "directory" -Path $WorkingFolder -Force }
if (!(Test-Path $WorkingDir -PathType Container))  { New-Item -ItemType "directory" -Path $WorkingDir -Force }
if (!(Test-Path $LogFolder -PathType Container))  { New-Item -ItemType "directory" -Path $LogFolder -Force }
if (!(Test-Path $archive_fullpath -PathType Container))  { New-Item -ItemType "directory" -Path $archive_fullpath -Force }

Write-Log -LogOutput "Debut"
Write-Log -LogOutput "Paramètre Bypass : $Bypass"

# --------- Téléchargement du fichier zip contenant iperf ---------
# On utilise systematiquement sans le proxy, et si l'ip externe est vide on teste avec le proxy, si ok on contiune.

$external_IPwp=$null
[system.net.webrequest]::defaultwebproxy = new-object system.net.webproxy($null)
[system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
[system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true

try {
    $external_IPwp=(Invoke-WebRequest -UseBasicParsing -uri "http://ifconfig.me/ip").Content
    $external_IP = $external_IPwp
    Write-Log -LogOutput "Appel API IP externe sans proxy : $external_IPwp"  
}
catch { 
    Write-Log -LogOutput "Exception appel API IP externe sans proxy (http://ifconfig.me/ip)"  

    #2e essai
    try {
        $external_IPwp=(Invoke-WebRequest -UseBasicParsing -uri "http://ifconfig.me/ip").Content
        $external_IP = $external_IPwp
        Write-Log -LogOutput "2eAppel API IP externe sans proxy : $external_IPwp"  
    }
    catch { 
        Write-Log -LogOutput "Exception appel API IP externe sans proxy (http://ifconfig.me/ip)"  
    }
}


# Ces 2 prochaine lignes semblent Obsolètes
$pattern = "^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$"
$IsIP = $external_IPwp -match $pattern

if(!$external_IPwp){

    $external_IPp=$null
    [system.net.webrequest]::defaultwebproxy = new-object system.net.webproxy(‘http://proxy.notaires.fr:8080’)
    [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true

    try {
        $external_IPp=(Invoke-WebRequest -UseBasicParsing -uri "http://ifconfig.me/ip").Content
        Write-Log -LogOutput "Appel API IP externe avec proxy : $external_IPp"  
        $external_IP = $external_IPp
    }
    catch {
        Write-Log -LogOutput "Exception appel API IP externe avec proxy (http://ifconfig.me/ip)"  

        #2e essai
        try {
            $external_IPp=(Invoke-WebRequest -UseBasicParsing -uri "http://ifconfig.me/ip").Content
            Write-Log -LogOutput "Appel API IP externe avec proxy : $external_IPp"  
            $external_IP = $external_IPp
        }
        catch {
            Write-Log -LogOutput "Exception appel API IP externe avec proxy (http://ifconfig.me/ip)"  
        }

    }
}


# On vérifie la présence d'un zip commençant par iperf dans le dossier C:\scripts
$zip_exist = [System.IO.File]::Exists($LocalPathArchiveIperf)

# --------- Si il existe on ne le télécharge pas et on continue ---------
if (!$zip_exist) {
    Write-Log -LogOutput "Download start"

    try {
        $R = Invoke-WebRequest -UseBasicParsing -Uri $zip_source -OutFile $LocalPathArchiveIperf
    }
    catch {
        Write-Log -LogOutput "Exception téléchargement Archive : $($_.Exception)"  
    }    

    Write-Log -LogOutput  "Download End"
    
}


# --------- On vérifie l'existance de l'executable sinon on quite ---------
$iperf_exist = Get-ChildItem -Path $archive_fullpath | where {$_.Name -like "*iperf*.exe"} -ErrorAction Ignore 

if (!$iperf_exist) {
    Write-Log -LogOutput "Iperf binary missing"
    Write-Log -LogOutput "Unzip Start"
    [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null # Chargement de la classe
    [System.IO.Compression.ZipFile]::ExtractToDirectory($LocalPathArchiveIperf, $WorkingDir) # Décompression du fichier zip dans C:\Windows\nom_du_fichier\
    Write-Log -LogOutput "Unzip End"
}

# Clean iperf result avant de lancer
if ([System.IO.File]::Exists($json_fullpath)) { Remove-Item -Path $json_fullpath }

# --------- Lancement des tests iperf  ---------


# Si l'IP externe n'est pas du REAL, le port 5201 peut être bloqué, il faut alors passer sur le port 80
#Detection si external_IPwp (without proxy) n'est pas null
$IsReal = $true
if ( $external_IPwp  ) { 
    $IsReal = $false 
} 
#Je force le fait que tout client est Navista car parfois avec une connexion Adnov, des flux internet sont différents
$IsReal = $false


# gestion des serveurs Iperf externes  https://iperf.fr/iperf-servers.php#public-servers
[PSCustomObject[]]$Global:iPerfServersExterneSettings = @() 
$Global:iPerfServersExterneSettings += [PSCustomObject]@{ Id = 1 ; Server = "ping.online.net"        ;  StartPort=5201 ; EndPort=5202  }
$Global:iPerfServersExterneSettings += [PSCustomObject]@{ Id = 2 ; Server = "ping6.online.net"       ;  StartPort=5201 ; EndPort=5202  }
$Global:iPerfServersExterneSettings += [PSCustomObject]@{ Id = 3 ; Server = "paris.testdebit.info"   ;  StartPort=9212 ; EndPort=9214  } # Start 9200 End 9240
$Global:iPerfServersExterneSettings += [PSCustomObject]@{ Id = 4 ; Server = "speed.as208196.net"     ;  StartPort=5201 ; EndPort=5202  }  
$Global:iPerfServersExterneSettings += [PSCustomObject]@{ Id = 5 ; Server = "bouygues.iperf.fr"      ;  StartPort=5200 ; EndPort=5201  }
$Global:iPerfServersExterneSettings += [PSCustomObject]@{ Id = 6 ; Server = "iperf.par2.as49434.net" ;  StartPort=9210 ; EndPort=9212  } # Start 9200 End 9240


[PSCustomObject]$Global:CurrentiPerfServersExterneSettings = @{ Id = 0 ; Port = 0  }

#$port=5201
#$server_ext="ping6.online.net"
#"bouygues.iperf.fr"


$Num_Try = 9
$wait2 = Get-Random -Minimum 10 -Maximum 40

Write-Log -LogOutput "Attente: $wait2"
Write-Log -LogOutput "Tentatives: $Num_Try"

if($IsReal){
# C'est un client REAL  
    Write-Log -LogOutput "Client REAL"
    Write-Log -LogOutput "Test iPerf REAL"
    $port=5201

	foreach ($_ in 1..$Num_Try ){
		
        Write-Log -LogOutput "Boucle N°: $_"
        $Speed_UP_real = iperf_start "iperf.genapicloud.com" $port

		if ($null -ne $Speed_UP_real) {
           #Cas où le Iperf a fonctionné, le Json n'était pas vide, on reste sur ces param de port et on fait le test de Download (-R pour Reverse)

           foreach ($_ in 1..$Num_Try){
                Write-Log -LogOutput "Boucle Reverse N°: $_"
                $Speed_Down_real = iperf_start "iperf.genapicloud.com" $port -Reverse $true
                if ($null -ne $Speed_Down_real) {
                    break
                }
                else {
                    $Speed_Down_real=""
                    Write-Log -LogOutput "    Erreur : $Global:ErroriPerf"
                }
                Start-Sleep $wait2
            }
           break #On sort de la boucle . on a un résultat ou atteint le nb maxi de tentatives
         }
         else {
           $Speed_UP_real="" ; $Speed_Down_real=""
           Write-Log -LogOutput "    Erreur : $Global:ErroriPerf"
         } 

        #Si on arrive la, c'est qu'on a pas Break, cad le 1er test d'upload n'a pas fonctionne, on reboucle		
        if ($port -eq 5201){$port=80}else{$port=5201} # On change le port de test à chaque itération
        Start-Sleep $wait2

	} # fin Foreach
    #"DOWN:$downloadspeed;UP:$uploadspeed"
    $iperfresult_real="DOWN:$Speed_Down_real;UP:$Speed_UP_real"
    Write-Log -LogOutput " Débit REAL : $iperfresult_real"   
    
    $Speed_UP_ext="" ; $Speed_Down_ext=""
    $iperfresult_ext="DOWN:$Speed_Down_ext;UP:$Speed_UP_ext"
    

} else {
# C'est pas un client REAL (possible de passer en dehors du proxy) - Donc un navista on passe sur le port 80 pour REAL #Navista a bloqué le port 5201

    Write-Log -LogOutput "client Navista"
    Write-Log -LogOutput "Test iPerf REAL"

	foreach ($_ in 1..$Num_Try ){
        
        $port=5201
        Write-Log -LogOutput "Boucle N°: $_"
        $Speed_UP_real = iperf_start "iperf.genapicloud.com" $port

		if ($null -ne $Speed_UP_real) {
           #Cas où le Iperf a fonctionné, le Json n'était pas vide, on reste sur ces param de port et on fait le test de Download (-R pour Reverse)

           foreach ($_ in 1..$Num_Try){
                Write-Log -LogOutput "Boucle Reverse N°: $_"
                $Speed_Down_real = iperf_start "iperf.genapicloud.com" $port -Reverse $true

                if ($null -ne $Speed_Down_real) {
                    break
                }
                else {
                    $Speed_Down_real=""
                    Write-Log -LogOutput "    Erreur : $Global:ErroriPerf"
                }
                Start-Sleep $wait2
            }
            break #On sort de la boucle . on a un résultat ou atteint le nb maxi de tentatives
         }
         else { 
            $Speed_UP_real="" ; $Speed_Down_real=""
            Write-Log -LogOutput "    Erreur : $Global:ErroriPerf"
         }                    

        #Si on arrive la, c'est qu'on a pas Break, cad le 1er test d'upload n'a pas fonctionne, on reboucle
		if ($port -eq 5201){$port=80}else{$port=5201} # On change le port de test à chaque itération normalement fermé
        Start-Sleep $wait2

	}#Fin Foreach
    $iperfresult_real="DOWN:$Speed_Down_real;UP:$Speed_UP_real"
    Write-Log -LogOutput " Débit REAL : $iperfresult_real"

    #Test de la pate internet seulement si type Navista detecté (navigation internet possible sans proxy)
    Write-Log -LogOutput " "
    Write-Log -LogOutput "Test iPerf INTERNET"
    foreach ($_ in 1..$Num_Try ){

        Write-Log -LogOutput "Boucle N°: $_"

        UpdateCurrentIperfExt_Settings
        $server_ext,$port = GetCurrentIperfExt_Settings_Srv_Port

		$Speed_UP_ext = iperf_start $server_ext $port # Port par defaut

		if ($null -ne $Speed_UP_ext) 
        {
          foreach ($_ in 1..$Num_Try){
                Write-Log -LogOutput "Boucle Reverse N°: $_"
                $Speed_Down_ext = iperf_start $server_ext $port -Reverse $true

                if ($null -ne $Speed_Down_ext) {
                    break
                }
                else {
                    $Speed_Down_ext=""
                    Write-Log -LogOutput "    Erreur : $Global:ErroriPerf"
                }
                Start-Sleep $wait2

          } #Fin Foreach
          break #On sort de la boucle . on a un résultat ou atteint le nb maxi de tentatives
        }
        else { 
            $Speed_UP_ext="" ; $Speed_Down_ext=""
            Write-Log -LogOutput "    Erreur : $Global:ErroriPerf"
        }  
        
        <#
		if ($server_ext -like "ping.online.net" -and $port -eq 5202 ) {$server_ext="bouygues.iperf.fr"}
        elseif ($server_ext -like "bouygues.iperf.fr" -and $port -eq 5202 ) {$server_ext="ping.online.net"}
        if ($port -eq 5201){$port=5202}else{$port=5201} # On change le port de test à chaque itération
        #>
        Start-Sleep $wait2

	} #Fin Foreach
    $iperfresult_ext="DOWN:$Speed_Down_ext;UP:$Speed_UP_ext"
    Write-Log -LogOutput " Débit INTERNET : $iperfresult_ext"	

}


# --------- Lancement des tests ping  ---------
$ping = new-object System.Net.NetworkInformation.ping
$reply = $ping.Send("www.google.fr")
$test_latency = $reply.RoundtripTime
$Date_check = Get-Date -format 'dd/MM/yyyy HH:mm:ss'
$checked_data = "$Date_check;$iperfresult_real;PING:$test_latency;$external_IP;$iperfresult_ext"
Write-Log -LogOutput " Fin - Données : $checked_data"

# Clean iperf result apres le lancement
# Remove-Item -Path $json_fullpath
  
# --------- Ajout au registre ---------

set-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "result" -Value "$checked_data" -force  
set-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "Lastweek" -Value "$thisweek" -force 
set-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Septeo\Supervision\iperf" -Name "LastYear" -Value "$Year" -force 

# --------- Finalisation des opérations ---------
Write-Log -LogOutput "Fin OK"
Exit


# => Fin du script ----------------------------------------------------------------------------------------------------------------------------------------------
