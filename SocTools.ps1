#SocTools.ps1
#Author: Scott Stage
#Created: 12/31/2024

if(-not (Get-Module powershell-yaml -ListAvailable)){
	Install-Module -Name powershell-yaml -Scope CurrentUser -Force #https://www.powershellgallery.com/packages/powershell-yaml/0.4.7
}
Import-Module powershell-yaml


$appProcess = $null
$config = Get-Content -Path 'config.yaml' | ConvertFrom-Yaml
$dateFormatPowershell = $config.dateFormatPowershell
$computerList = $config.computerList
$delimiter = $config.delimiter
$hostname = $config.hostname
$port = $config.port
$logFile = $config.logFile 


# Function to Launch app.py
function Start-AppPy {
    # Start app.py with named pipe argument
    $process = Start-Process -FilePath "python-3.12.0-embed\python.exe" -ArgumentList "app.py" -PassThru
    # Return information about the process
    return @{
        Process = $process
    }
}

# Function to write to log
function LogWrite([string]$logMessage)
{
    $currentTime = Get-Date -Format $dateFormatPowershell
     try {
        Add-Content -Path $logFile -Value "$currentTime - SocTools.ps1: $logMessage" -ErrorAction Stop
    }
    catch {
        Write-Host "Error writing to log file $($logFile): $($_.Exception.Message)"
    }
}

# Function to handle errors consistently
function Write-ErrorResponse {
    param (
        [string]$FunctionName,
        [System.Exception]$Exception
    )
    $errorMessage = "Error in $FunctionName : $($Exception.Message)"
    LogWrite -logMessage $errorMessage
    return @{
        Success = $false
        Error = $errorMessage
    }
}

# Define a custom class to maintain property order
class ResponseObject {
    [string]$action
    [bool]$success
    [object]$output
}

# Function to display formatted table output
function Format-TableOutput {
    param (
        [object]$Data
    )
    if ($Data) {
        $output = $Data | Format-Table -AutoSize | Out-String
        LogWrite -logMessage "Formatted Table Output: $($output)"
        $output
    } else {
        $noDataMessage = "No data to display."
        LogWrite -logMessage $noDataMessage
        $noDataMessage
    }
}

# Function to display formatted list output
function Format-ListOutput {
     param (
        [object]$Data
    )
    if ($Data) {
        $output = $Data | Format-List | Out-String
        LogWrite -logMessage "Formatted List Output: $($output)"
        $output
    } else {
        $noDataMessage = "No data to display."
        LogWrite -logMessage $noDataMessage
        $noDataMessage
    }
}

# Function to split user input by newlines
function Split-UserInput {
    param (
        [string]$Input
    )
    if (-not [string]::IsNullOrEmpty($Input)) {
        return $Input -split '\n'
    } else {
        return @()
    }
}

function keepalive($result){
    try{
        $response = [ResponseObject]::new()
        $response.action = "keepalive"
        $response.success = $true
        return $response | ConvertTo-Json
    }
	catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_.Exception
	}
}

function ConnectToExchangeOnline(){
	$connectionStatus = ""
	try{
		LogWrite("Getting connection information")
		$getsessions = Get-ConnectionInformation
		LogWrite("Connection information : $getsessions")
		if($getsessions.State -eq 'Connected' -and 
			$getsessions.TokenStatus -eq 'Active' -and 
			$getsessions.IsEopSession -eq 'True' -and
			$getsessions.ConnectionUsedForInbuiltCmdlets -eq 'True'){
				$connectionStatus = "Connected"
		}else{
			$connectionStatus = "Disconnected"
		}
		while($connectionStatus -eq "Disconnected"){
			echo "Connecting IPPSession..."
			Connect-IPPSSession
			echo "Connecting ExchangeOnline..."
			Connect-ExchangeOnline
			$getsessions = Get-ConnectionInformation
			if($getsessions.State -eq 'Connected' -and 
				$getsessions.TokenStatus -eq 'Active' -and 
				$getsessions.IsEopSession -eq 'True' -and
				$getsessions.ConnectionUsedForInbuiltCmdlets -eq 'True'){
				$connectionStatus = "Connected"
			}else{
				$connectionStatus = "Disconnected"
			}
		}
		
        $response = [ResponseObject]::new()
        $response.action = "ConnectToExchangeOnline"
        $response.success = $true
		$response.output = $connectionStatus
        return $response | ConvertTo-Json
    }
	catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_.Exception
	}
}

function CheckExoConnection(){
	$response = [ResponseObject]::new()
	$connectionStatus = ""
	try{
		LogWrite -logMessage "Getting connection information"
		$getsessions = Get-ConnectionInformation
		LogWrite -logMessage "Connection information : $getsessions"
		if($getsessions.State -eq 'Connected' -and 
			$getsessions.TokenStatus -eq 'Active' -and 
			$getsessions.IsEopSession -eq 'True' -and
			$getsessions.ConnectionUsedForInbuiltCmdlets -eq 'True'){
				$connectionStatus = "Connected"
		}else{
			$connectionStatus = "Disconnected"
		}
		
        
        $response.action = "CheckExoConnection"
        $response.success = $true
		$response.output = $connectionStatus
        return $response | ConvertTo-Json
    }
	catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_.Exception | ConvertTo-Json
	}
}

function GetSocPcInfo($result){
    $response = [ResponseObject]::new()
    $systemList = @{}
	$diskDrives = ""
    try{
        $softwareResultsList = @{}
        # Iterate through each computer in the list
        foreach ($computer in $computerList) {
            if ($true) { #Verify this block is entered.
                LogWrite("Computer $computer is reachable.")
                # --- Gather System Information ---
                LogWrite "  Gathering system information..."
                $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computer -ErrorAction SilentlyContinue # Temporarily change to Stop for testing
                if ($computerSystem) {
                    $model = $($computerSystem.Model)
                    $manufacturer = $($computerSystem.Manufacturer)
                    $memory = $([math]::Round(($computerSystem.TotalPhysicalMemory / 1GB), 2))
                    $computerName = $($computerSystem.Name)
                } else {
                    LogWrite "    Error: Could not retrieve Win32_ComputerSystem data."
                }

                # --- Gather Disk Space Information ---
                LogWrite "  Gathering disk space information..."
                $diskDrives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $computer -ErrorAction SilentlyContinue # Temporarily change to Stop for testing
                if($diskDrives){
                   foreach ($disk in $diskDrives) {
                        $drive = "$($disk.DeviceID) $($disk.VolumeName)"
                        $driveSize = $([math]::Round(($disk.Size / 1GB), 2))
                        $freeSpace = $([math]::Round(($disk.FreeSpace / 1GB), 2))
                    }
                }else{
                    LogWrite "    Error: Could not retrieve Win32_LogicalDisk data."
                }
                # --- Gather Installed Software Information ---
                LogWrite "  Gathering installed software information..."
                $ForcePointPath = "C:\Program Files\Websense\Websense Endpoint\F1EUI.exe"
				#$ForcePointFileVersion = (Get-Command $ForcePointPath).FileVersionInfo.FileVersion
				
				$ZscalerPath = "C:\Program Files\Zscaler\ZSATray\ZSATray.exe"
				#$ZscalerFileVersion = (Get-Command $ZscalerPath).FileVersionInfo.FileVersion
				
				$CrowdStrikePath = "C:\Program Files\CrowdStrike\CSFalconService.exe"
				#$CrowdStrikeFileVersion = (Get-Command $CrowdStrikePath).FileVersionInfo.FileVersion
				
				if (Test-Path -Path "C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe") {
						$CiscoPath = "C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe"
						$CiscoFileVersion = (Get-Command $CiscoPath).FileVersionInfo.FileVersion
				} else {
					$CiscoFileVersion = "Not Installed"
				}
                $lastreboot = [System.Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem -ComputerName . -ErrorAction SilentlyContinue).LastBootUpTime) #Temporarily changed for debug purposes.
            } else {
                LogWrite -logMessage "    Error: $computer is unreachable"
            }
            $systemList["$computer"] = @{
                "computername" =  $computerName
                "currentuser" =  $currentuser
                "manufacturer" =  $manufacturer
                "lastreboot" = $lastreboot
                "pingresult" = $pingResult
                "drivesize" =  $driveSize
                "freespace" =  $freeSpace
                "memory" =  $memory
                "drive" =  $drive
                "model" = $model
                "os" =  $os
                #"forcepoint" = $ForcePointFileVersion
                #"zscaler" = $ZscalerFileVersion
                #"crowdstrike" = $CrowdStrikeFileVersion
                "ciscoanyconnect" = $CiscoFileVersion
            }
        }        
		
		
        $response.action = $($MyInvocation.MyCommand.Name)
        $response.success = $true
        $response.output = $systemList 
        return $response | ConvertTo-Json
    }
    catch{
        return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
    }
}

function GetCurrentUserInfo($result){
    $response = [ResponseObject]::new()
    $systemList = @{}
    try{
        $tableSubstring = (query user)[0] -split '\s+'
        $tableHeaders = '         '   
        $tableHeaders += $tableSubstring[1] + '                                       ' + $tableSubstring[2] + '         ' + $tableSubstring[3] + ' ' + $tableSubstring[4] + '       ' + $tableSubstring[5] + '   ' + $tableSubstring[6]
        foreach ($computer in $computerList) {
			$string = ""
			$userID = $null
			$state = ""
			$sessionName = ""
			
            LogWrite -logMessage "Getting logged in user for $computer :"
            if (!(Test-Connection $computer -Count 1 -Quiet)){
                 LogWrite -logMessage "    Error: $computer is unreachable"
            }
            else{
                $userTable = (query user /server:$computer 2>$null)
                $string = $computer
                $username = ""
                Foreach($o in $userTable){
                    if($o -match 'Active'){
                        $Parsed_Server = $o -split '\s+'
						$userID = $Parsed_Server[1]
                        $sessionName = $Parsed_Server[2]
                        $state = $Parsed_Server[4]
                        $username = net user /domain $userID
                        $username = $username[3].Substring(9).Trim()
                        break
                    }                               
                }
				LogWrite -logMessage "UserId = $userID // Username = $username"
                if($null -ne $userID){
					LogWrite -logMessage "String before replace: $string"
                    $username = $userID.Replace($userID, "($userID) $username")
					LogWrite -logMessage "String after replace: $string"
                }                      
            }
            $string = $string -split '\s+'
            $systemList["$computer"] = @{
                "computer" =  $computer
                "username" =  $username
                "sessionname" =  $sessionName
                "state" =  $state
            }
        }
        $response.action = $($MyInvocation.MyCommand.Name)
        $response.success = $true
        $response.output = $systemList
        return $response | ConvertTo-Json
    }catch{
        return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
    }
}

function ConnectRdp($result){
    $targetComputer = $result.input
    try{
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = "$env:windir\system32\mstsc.exe"
        $processStartInfo.Arguments = "/v:$targetComputer"
        $processStartInfo.UseShellExecute = $true #Required to launch programs
        [System.Diagnostics.Process]::Start($processStartInfo)
        LogWrite -logMessage "Successfully started RDP with argument: $targetComputer"

        $output = @{
            "message" =  "Started new rpd process with argument: $targetComputer"
        }
        $response = [ResponseObject]::new()
        $response.action = $($MyInvocation.MyCommand.Name)
        $response.success = $true
        $response.output = $output
        return $response | ConvertTo-Json
    }catch{
        return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_ | ConvertTo-Json
    }
}

function RevokeMessage($userInput){
    LogWrite -logMessage "Starting RevokeMessage function."
    try{
        $MessageIDs = Split-UserInput -Input $userInput
        if($MessageIDs){
            $output = ""
            foreach ($ID in $MessageIDs)
            {
               $output += Format-TableOutput (Get-OMEMessageStatus -MessageId $ID | Select-Object Subject, IsRevocable, Revoked)
            }
            return @{
                Success = $true
                Output = $output
            }
        }
        else{
            $noMessageId = "No Message ID's provided"
            LogWrite -logMessage $noMessageId
            return @{
                Success = $false
                Error = $noMessageId
            }
        }
	}
	catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
	}
}

function SetSearchName($searchName){
    LogWrite -logMessage "Starting SetSearchName function."
	try{
		$searchData = Get-ComplianceSearch -Identity $searchName -ErrorAction Stop
        $output =  Format-ListOutput $searchData
        return @{
            Success = $true
            Output = $output
        }
	}
	catch{
        return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
	}
    LogWrite -logMessage "Finished SetSearchName function."
}


function PerformHardDelete($searchName){
    LogWrite -logMessage "Starting PerformHardDelete function."
    try{
        $output = New-ComplianceSearchAction -SearchName '$searchName' -Purge -PurgeType HardDelete | Format-Table
        #$output = whoami
        return @{
            Success = $true
            Output = $output
        }
    }
	catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
	}
    LogWrite -logMessage "Finished PerformHardDelete function."
}

function UpdatePurgeStatus($searchName, $purgeString){
    LogWrite -logMessage "Starting UpdatePurgeStatus function."
	try{
        $purgeStatusData = (Get-ComplianceSearchAction -Identity "$searchName$purgeString" | Format-List -Property SearchName, Action, RunBy, JobStartTime, JobEndTime, Status, Errors | out-string)
        return @{
            Success = $true
            Output = $purgeStatusData
        }
    }
	catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
	}
    LogWrite -logMessage "Finished UpdatePurgeStatus function."
}

function CheckRevokeStatus($userInput){
    LogWrite -logMessage "Starting CheckRevokeStatus function."
	try{
		$MessageIDs = Split-UserInput -Input $userInput
        $output = ""
        if($MessageIDs){
            foreach ($ID in $MessageIDs)
            {
                $output += Format-TableOutput (Get-OMEMessageStatus -MessageId $ID | Select-Object Subject, IsRevocable, Revoked)
            }
            return @{
                Success = $true
                Output = $output
            }
        }
        else{
            $noMessageId = "No Message ID's provided"
            LogWrite -logMessage $noMessageId
            return @{
                Success = $false
                Error = $noMessageId
            }
        }
	}catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
	}
    LogWrite -logMessage "Finished CheckRevokeStatus function."
}

function SetTimeRange(){
    LogWrite -logMessage "Starting SetTimeRange function."
	try{
	   #Logic for SetTimeRange here
		#Throw "Simulated Error in SetTimeRange"
        return @{
            Success = $true
            Output = "Set Time Range Logic Ran."
        }
	}
	catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
	}
    LogWrite -logMessage "Finished SetTimeRange function."
}

function SetUser(){
    LogWrite -logMessage "Starting SetUser function."
	try{
	   #Logic for SetUser here
		#Throw "Simulated Error in SetUser"
        return @{
            Success = $true
            Output = "Set User Logic Ran."
        }
	}
	catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
	}
    LogWrite -logMessage "Finished SetUser function."
}
function SetOperations(){
    LogWrite -logMessage "Starting SetOperations function."
	try{
	   #Logic for SetOperations here
		#Throw "Simulated Error in SetOperations"
        return @{
            Success = $true
            Output = "Set Operations Logic Ran."
        }
	}
	catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
	}
    LogWrite -logMessage "Finished SetOperations function."
}
function SetMessageID(){
    LogWrite -logMessage "Starting SetMessageID function."
	try{
	   #Logic for SetMessageID here
		#Throw "Simulated Error in SetMessageID"
        return @{
            Success = $true
            Output = "Set Message ID Logic Ran."
        }
	}
	catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
	}
    LogWrite -logMessage "Finished SetMessageID function."
}
function SEARCH(){
    LogWrite -logMessage "Starting SEARCH function."
		try{
	   #Logic for SEARCH here
		#Throw "Simulated Error in SEARCH"
        return @{
            Success = $true
            Output = "Search Logic Ran."
        }
		}
		catch{
			return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
		}
    LogWrite -logMessage "Finished SEARCH function."
}
function ClearResults(){
    LogWrite -logMessage "Starting ClearResults function."
	try{
        return @{
            Success = $true
            Output = "ClearResults"
        }
	}
	catch{
        return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
	}
    LogWrite -logMessage "Finished ClearResults function."
}


function main(){
    # Start app.py and get the pipe information
    Write-Host "-------------------------------------------------------------"
    Write-Host "------------------- SocTools Initializing -------------------"
    Write-Host "-------------------------------------------------------------"
    LogWrite -logMessage "-------------------------------------------------------------"
    LogWrite -logMessage "------------------- SocTools Initializing -------------------"
    LogWrite -logMessage "-------------------------------------------------------------"

    $appInfo = Start-AppPy
    $appProcess = $appInfo.Process # Assign the value here in the script
    Write-Host "SocTools.ps1 started. Process ID: $($PID)"
    Write-Host "app.py started. Process ID: $($appProcess.Id)"
    LogWrite -logMessage "SocTools.ps1 started. Process ID: $($PID)"
    LogWrite -logMessage "app.py started. Process ID: $($appProcess.Id)"

    # Using .NET classes for sockets
    $server_socket = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($hostname), $PORT)
    $server_socket.Start()

    Write-Host "Listening on $($hostname):$($PORT)"
    LogWrite "Listening on $($hostname):$($PORT)"

    # Set up event to signal socket is up
    $tcp_ready = New-Object System.Threading.ManualResetEvent($false)
    $tcp_ready.Set() | Out-Null

    # Accept a client connection
    $client_socket = $server_socket.AcceptTcpClient()
    $client_addr = $client_socket.Client.RemoteEndPoint
    Write-Host "Accepted TCP connection from $($client_addr)"
    LogWrite "Accepted TCP connection from $($client_addr)"
    Write-Host "Connection Established!"
    Write-Host "SocTools.ps1($($hostname):$($PORT)) <---> app.py($($client_addr))"
    LogWrite -logMessage "Connection Established!"
    LogWrite -logMessage "SocTools.ps1($($hostname):$($PORT)) <---> app.py($($client_addr))"
    Write-Host "-------------------------------------------------------------"
    Write-Host "------- SocTools is running at http://127.0.0.1:5000 --------"
    Write-Host "-------------------------------------------------------------"
    LogWrite -logMessage "-------------------------------------------------------------"
    LogWrite -logMessage "------- SocTools is running at http://127.0.0.1:5000 --------"
    LogWrite -logMessage "-------------------------------------------------------------"

    try{
        # Handle the connection in this block.
        $stream = $client_socket.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)

        while ($client_socket.Connected)
        {
            if($stream.DataAvailable)
            {
                $command = $reader.ReadLine();
                LogWrite "Command received: $command";
                # Handle Command and Return Result
                $result = try{
                    $command | ConvertFrom-Json
                } catch {
                    @{
                        "error" = "Error parsing JSON";
                        "success" = $false
                    }
                }
                if ($result) {
                    $action = $result.action
                    if($action){
                        $response = try {
                            &$action($result)
                        } catch {
                            $response = @{
                                "error" = $($_.Exception.Message);
                                "success" = $false;
                                "action" = $action
                            } | ConvertTo-Json
                            LogWrite -logMessage "Error response generated: $($_)"; # Log the error response
                        }
						LogWrite "Sending response to app.py: $($response)"
                        $writer.WriteLine($response + $delimiter)
                        $writer.Flush()
                    }
                    else {
                        $response = @{
                            "error" = "No action received";
                            "success" = $false;
                        } | ConvertTo-Json
                        $writer.WriteLine($response + $delimiter)
                        $writer.Flush()
                    }
                }
                else {
                    $response = @{
                        "error" = "No command received";
                        "success" = $false;
                    } | ConvertTo-Json
                    $writer.WriteLine($response + $delimiter)
                    $writer.Flush()
                }
            }else{
                Start-Sleep -Milliseconds 100 # Check if data is available 10x a second
            }
        }
    }
    catch{
        Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_
    }
    finally
    {
        # Clean Up Connection
        $reader.Close()
        $writer.Close()
        $client_socket.Close();
        $server_socket.Stop();
        LogWrite "TCP connection from $($client_addr) closed."
        if ($appProcess) {
            LogWrite -logMessage "Terminating app.py"
            $appProcess | Stop-Process
        }
    }
}


main