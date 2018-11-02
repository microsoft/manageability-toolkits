<#
	.SYNOPSIS
		The Core Monitoring Toolkit automates the deployment of an example set of log alerts to Azure Monitor Log Analytics.

	.DESCRIPTION
		The Core Monitoring Toolkit automates the deployment of an example set of log alerts to Azure Monitor Log Analytics.
		The toolkit consists of configuration file containing log alert definitions and a script that deploys the alerts.

	.Parameter SubscriptionID
		Specifies the Azure Subscription ID for the workspace where the alerts will be created.
	.Parameter WorkspaceName
		Specifies the name for the log analytics workspace where the alerts will be created.
	.Parameter ResourceGroup
		Specifies the resource group of the workspace where the alerts will be created.
	.Parameter Location
		Specifies the location of the workspace where the alerts will be created.
	.Parameter NewActionGroupName
		Specifies the name of the action group to be added to all alerts created by this toolkit. Default is '<workspacename>-email-ag1', where workspacename is the name of the workspace.
	.Parameter ActionGroupShortName
		Specifies the short name (12 char max, no spaces) of the action group to be added to all alerts created by this toolkit. Default is 'CoreAlert'.
	.Parameter AlertEmailAddress
		Specifies the email address that will be configured for the action group to be added to all alerts created by this toolkit.
	.Parameter ExistingActionGroupName
		Specifies the name of an existing action group to be added to all alerts created by this toolkit.
	.Parameter ConfigPath
		Specifies the path to the JSON file containing the alert configurations. Default is '.\DefaultAlertConfig.json'.

	.EXAMPLE 
	   .\New-CoreAlerts.ps1 -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -WorkspaceName 'alertsWorkspace' -ResourceGroup 'alertsRG' -Location 'East US'
	   
	   This command will run the Core Monitoring Toolkit script with the provided parameters.


	.EXAMPLE
	   .\New-CoreAlerts.ps1
	   
	   This command will run the Core Monitoring Toolkit script and prompt the user for required parameters.


	.EXAMPLE 
	   .\New-CoreAlerts.ps1 -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -ExistingActionGroupName 'useractiongroupname' -WorkspaceName 'alertsWorkspace' -ResourceGroup 'alertsRG' -Location 'East US' 
	   
	   This command will run the Core Monitoring Toolkit script with the provided parameters, adding the existing action group named 'useractiongroupname' to all alerts created by the toolkit.

		
	.LINK
	https://github.com/Microsoft/manageability-toolkits

	.Notes
		NAME:     New-CoreAlerts
		AUTHOR(s): Arun Kumar Rajendra <arunkra@microsoft.com>, Matt Carlson <macarlso@microsoft.com>
		LASTEDIT: 10/31/2018
		KEYWORDS: OMS, Log Analytics, Alerts, Core Alerts, Log Alerts, Azure Monitor
#>


# TODO: Add parameter sets for action group parameters
param (
	[Parameter(Mandatory=$true)]
	[string]$SubscriptionId,
	
	[Parameter(Mandatory=$true)]
	[string]$WorkspaceName,
	
	[Parameter(Mandatory=$true)]
	[string]$ResourceGroup,
	
	[Parameter(Mandatory=$true)]
	[string]$Location,
	
	[Parameter(Mandatory=$false)]
	[string]$NewActionGroupName,
	
	[Parameter(Mandatory=$false)]
	[string]$ActionGroupShortName = "CoreAlert",
	
	[Parameter(Mandatory=$false)]
	[string]$ExistingActionGroupName,
	
	[Parameter(Mandatory=$false)]
	[string]$AlertEmailAddress,
	
	[Parameter(Mandatory=$false)]
	[string]$ConfigPath = ".\DefaultAlertConfig.json"
)


# Create a new action group
function New-ActionGroup
{
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$SubscriptionID,

		[Parameter(Mandatory=$true)]
		[string]$ResourceGroup,
	
		[Parameter(Mandatory=$true)]
		[string]$AlertEmailAddress,
		
		[Parameter(Mandatory=$true)]
		[string]$ActionGroupName,
		
		[Parameter(Mandatory=$true)]
		[string]$ActionGroupShortName
	)
	
	try
	{
		<#
		Extract the user name from the email address and build the email action name from it.
		e.g.
		If Email = emailaction@microsoft.com
		$emailActionName = "email-emailaction"
		#>

		$emailUser = $AlertEmailAddress.Split("@")[0]
		$emailActionName = "email-$emailUser"
		
		Write-Verbose "Variable AlertEmailAddress = $AlertEmailAddress"
		Write-Verbose "Variable emailUser = $emailUser"
		Write-Verbose "Variable emailActionName = $emailActionName"
		
		# Create the resource ID and properties to use when creating the action group using New-AzureRmResource cmdlet.
		$ResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/microsoft.insights/actionGroups/$ActionGroupName"
		$GroupProperties = [PSCustomObject]@{
			groupShortName = $ActionGroupShortName
			enabled = $true
			emailReceivers = @([pscustomobject]@{name = $emailActionName;emailAddress = $AlertEmailAddress})	
		}

		# Create the action group
		New-AzureRmResource -Location "Global" -ResourceId $ResourceId -Properties $GroupProperties -ApiVersion "2017-04-01" -Force
	}
	catch 
	{ 
		$ErrorMessage = $_.Exception.Message
		Write-Error "Error occurred while creating action groups: $ErrorMessage"
		Exit 1
	}
}

# Create a new saved search
function New-AlertSavedSearch
{
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$SubscriptionID,

		[Parameter(Mandatory=$true)]
		[string]$ResourceGroup,

		[Parameter(Mandatory=$true)]
		[string]$WorkspaceName,

		[Parameter(Mandatory=$true)]
		[string]$Apiversion,

		[Parameter(Mandatory=$true)]
		[string]$SavedSearchId,
		
		[Parameter(Mandatory=$true)]
		[PSCustomObject]$Properties
	)
	
	Write-Verbose "Creating new alert saved search"
	try
	{
		# Create the resource ID to use when creating the saved search using New-AzureRmResource cmdlet.
		$ResourceId = "/subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/savedSearches/$SavedSearchId/"
		Write-Verbose "ResourceId: $ResourceId"
		Write-Verbose "Saved Search Query: $($Properties.Query)"

		# Create the saved search
		New-AzureRmResource -ResourceId $ResourceId -Properties $Properties -ApiVersion "2017-03-15-preview" -Force
	}
	catch
	{
		$ErrorMessage = $_.Exception.Message
		Write-Error "Error occurred while creating Saved searches: $ErrorMessage"
		Exit 1 
	}
}

# Create a new schedule for the saved search
function New-AlertSchedule
{
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$SubscriptionID,

		[Parameter(Mandatory=$true)]
		[string]$ResourceGroup,

		[Parameter(Mandatory=$true)]
		[string]$WorkspaceName,

		[Parameter(Mandatory=$true)]
		[string]$Apiversion,

		[Parameter(Mandatory=$true)]
		[string]$SavedSearchId,
		
		[Parameter(Mandatory=$true)]
		$BearerToken,
		
		[Parameter(Mandatory=$true)]
		[string]$ScheduleId,
		
		[Parameter(Mandatory=$true)]
		[PSCustomObject]$Properties
	)
	
	Write-Verbose "Creating new alert schedule"
	try
	{
		# Get json in the format of "{'properties': { 'Interval': 10, 'QueryTimeSpan':10, 'Active':'true' }"
		$scheduleJson = [PSCustomObject]@{properties = $Properties} | ConvertTo-Json
		
		# Build the header for the API call
		$header = @{
			'Content-Type'='application\json'
			'Authorization'= $BearerToken
		}
		
		# Build the URI for the API call
		$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/savedSearches/$SavedSearchId/schedules/$($ScheduleId)?api-version=$($Apiversion)"
		Write-Verbose "URI: $uri"
		Write-Verbose "Json payload: $scheduleJson"
		
		# Create the alert schedule
		Invoke-RestMethod -Uri $uri -Headers $header -Method Put -Body $scheduleJson -ContentType "application/json"
		
		<#
			#Used only for New-AzureRmResource method which works, but is currently not supported.
			$ResourceId = "/subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/savedSearches/$SavedSearchId/schedules/$ScheduleId/"
			$scheduleProperties = [PSCustomObject]@{
				Interval = 10
				QueryTimeSpan = 10
				Active = "true"
			}

			# Using the API directly for now since nested resources is not supposed to work with this command. This does work though so we re-enable at a later date 
			New-AzureRmResource -ResourceId $ResourceId -Properties $scheduleProperties -ApiVersion $Apiversion -Force
		#>
	}
	catch
	{
		$ErrorMessage = $_.Exception.Message
		Write-Error "Error occurred while creating Schedule: $ErrorMessage"
		Exit 1
	}
}

# Create a new action for a schedule, completing the alert configuration
function New-AzureAlert
{
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$SubscriptionID,

		[Parameter(Mandatory=$true)]
		[string]$ResourceGroup,
		
		[Parameter(Mandatory=$true)]
		[string]$ActionResourceGroup,

		[Parameter(Mandatory=$true)]
		[string]$WorkspaceName,

		[Parameter(Mandatory=$true)]
		[string]$Apiversion,

		[Parameter(Mandatory=$true)]
		[string]$SavedSearchId,

		[Parameter(Mandatory=$true)]
		[string]$ScheduleId,

		[Parameter(Mandatory=$true)]
		[string]$AlertId,
		
		[Parameter(Mandatory=$true)]
		[string]$ActionGroupName,
		
		[Parameter(Mandatory=$true)]
		$BearerToken,
		
		[Parameter(Mandatory=$true)]
		[PSCustomObject]$Properties
	)
	
	Write-Verbose "Creating new alert"

	# Build the header for the API call
	$header = @{
		'Content-Type'='application\json'
		'Authorization'= $BearerToken
	}
	
	# Build the URI for the API call
	$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/savedSearches/$SavedSearchId/schedules/$ScheduleId/actions/$($AlertId)?api-version=$($Apiversion)"
	
	# Depth parameter must be large enough so that arrays deeper into the JSON aren't converted to a single line of text.
	$alertsJson = [PSCustomObject]@{properties = $Properties} | ConvertTo-Json -Depth 5

	# Replace with actual action group, subscription and resource group names.
	$alertsJson = $alertsJson.Replace("samplecoreactiongroup", $ActionGroupName)
	$alertsJson = $alertsJson.Replace("subscrname", $SubscriptionId)
	$alertsJson = $alertsJson.Replace("resourcegrp", $ActionResourceGroup)
	
	Write-Verbose "URI: $uri"
	Write-Verbose "Json payload: $alertsJson"
	
	# Create the alert
	Invoke-RestMethod -Uri $uri -Headers $header -Method Put -Body $alertsJson -ContentType "application/json"
}

function Update-WorkspaceEventCollection
{
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$ResourceGroup,
		
		[Parameter(Mandatory=$true)]
		[string]$WorkspaceName,
		
		[Parameter(Mandatory=$true)]
		[PSCustomObject]$EventLogConfig
	)
	# Configure log analytics workspace with specified event log collections


	Write-Verbose "Entering function: 'Update-WorkspaceEventCollection'"
	Write-Verbose "Resource Group Name: '$ResourceGroup'"
	
	Write-Verbose "Getting current windows event collection configuration from workspace"
	$CurrentWindowsEventConfig = Get-AzureRmOperationalInsightsDataSource -WorkspaceName $WorkspaceName -ResourceGroupName $ResourceGroup -Kind WindowsEvent | Select-Object `
		Name, `
		@{n='EventLogName'; e={ $_.Properties.EventLogName }}, `
		@{n='CollectErrors'; e={$_.Properties.EventTypes.EventType -contains 'Error' }}, `
		@{n='CollectWarnings'; e={$_.Properties.EventTypes.EventType -contains 'Warning' }}, `
		@{n='CollectInformation'; e={$_.Properties.EventTypes.EventType -contains 'Information' }}
	
	#
	Write-Verbose "Looping through events from even log configuration"
	foreach ( $EventLogItem in $EventLogConfig )
	{
		Write-Verbose "Processing event '$($EventLogItem.EventLogName)'"

		# Create a hashtable to track whether Error, Warning or Information event types should be collected for this event log
		$EventArgs = @{}
		$EventArgs.Add('EventLogName', $EventLogItem.EventLogName)

		if ( $EventLogItem.Error )
		{
			$EventArgs.Add('CollectErrors', $null)
		}
		if ( $EventLogItem.Warning )
		{
			$EventArgs.Add('CollectWarnings', $null)
		}
		if ( $EventLogItem.Information )
		{
			$EventArgs.Add('CollectInformation', $null)
		}

		# Get configuration if this event log is already configured in the log analytics workspace
		$ThisEvent = $CurrentWindowsEventConfig | Where-Object { $_.EventLogName -eq $EventLogItem.EventLogName }

		# Enable the event log collection if it is not already configured.
		if ( -not $ThisEvent )
		{
			Write-Verbose "Event log not configured";

			# Build the name in the format log analytics expects
			$NewDataSourceName = "DataSource_WindowsEvent_$(  (New-Guid).ToString() )"
			Write-Verbose $NewDataSourceName

			# Configure the event in the specified workspace
			New-AzureRmOperationalInsightsWindowsEventDataSource -WorkspaceName $WorkspaceName -ResourceGroupName $ResourceGroup -Name $NewDataSourceName @EventArgs | Out-Null
		}
		else
		{
			Write-Verbose "Event log collection already configured"
		}
	}
	
	Write-Verbose "Exiting function: 'Update-WorkspaceEventCollection'"
}

function Update-WorkspacePerfCollection
{
	param
	(
		[Parameter(Mandatory=$true)]
		$Workspace,
		
		[Parameter(Mandatory=$true)]
		[PSCustomObject]$PerfCollectionConfig
	)
	# Configure log analytics workspace with specified performance counter collections


	Write-Verbose "Entering function: 'Update-WorkspacePerfCollection'"

	Write-Verbose "Getting current windows event collection configuration from workspace"
	$CurrentWindowsPerfConfig = Get-AzureRmOperationalInsightsDataSource -Workspace $Workspace -Kind WindowsPerformanceCounter | Select-Object `
		Name, `
		@{n='ObjectName'; e={ $_.Properties.ObjectName }}, `
		@{n='InstanceName'; e={$_.Properties.InstanceName }}, `
		@{n='IntervalSeconds'; e={$_.Properties.IntervalSeconds }}, `
		@{n='CounterName'; e={$_.Properties.CounterName }}, `
		@{n='CollectorType'; e={$_.Properties.CollectorType }}
	
	Write-Verbose "Looping through events from even log configuration"
	foreach ( $PerfCollectionItem in $PerfCollectionConfig )
	{
		Write-Verbose "Processing performance collector '$($PerfCollectionItem.ObjectName)($($PerfCollectionItem.InstanceName))\$($PerfCollectionItem.CounterName)'"

		# Create a hashtable to track the ObjectName, InstanceName, IntervalSeconds and CounterName values
		$EventArgs = @{}
		$EventArgs.Add('ObjectName', $PerfCollectionItem.ObjectName)
		$EventArgs.Add('InstanceName', $PerfCollectionItem.InstanceName)
		$EventArgs.Add('IntervalSeconds', $PerfCollectionItem.IntervalSeconds)
		$EventArgs.Add('CounterName', $PerfCollectionItem.CounterName)

		# Get configuration if this performance counter is already configured in the log analytics workspace
		$ThisPerfCollector = $CurrentWindowsPerfConfig | Where-Object {  ($_.ObjectName -eq $PerfCollectionItem.ObjectName ) -and  ($_.CounterName -eq $PerfCollectionItem.CounterName ) -and ($_.CounterName -eq $PerfCollectionItem.CounterName ) }

		# Enable the performance counter collection if it is not already configured.
		if ( -not $ThisPerfCollector )
		{
			Write-Verbose "Perf collector not configured";

			# Build the name in the format log analytics expects
			$NewDataSourceName = "DataSource_PerfCounter_$(  (New-Guid).ToString() )"
			Write-Verbose $NewDataSourceName

			# Configure the event in the specified workspace
			New-AzureRmOperationalInsightsWindowsPerformanceCounterDataSource -Workspace $Workspace -Name $NewDataSourceName @EventArgs | Out-Null
		}
		else
		{
			Write-Verbose "Perf counter collection already configured"
		}
	}
	
	Write-Verbose "Exiting function: 'Update-WorkspacePerfCollection'"
}

function Login
{
	# Attempt to login to Azure
    $needLogin = $true
    Try 
    {
        $content = Get-AzureRmContext
        if ($content) 
        {
			# Verify there is an active session
            $needLogin = ([string]::IsNullOrEmpty($content.Account))
        } 
    } 
    Catch 
    {
        if ($_ -like "*Login-AzureRmAccount to login*") 
        {
            $needLogin = $true
        } 
        else 
        {
            throw
        }
    }

    if ($needLogin)
    {
		# Perform the login if needed
        Login-AzureRmAccount
    }
}


function Get-AzureRmCachedAccessToken
{
    # Function found here undet MIT license
    # https://gallery.technet.microsoft.com/scriptcenter/Easily-obtain-AccessToken-3ba6e593
    $ErrorActionPreference = 'Stop'
  
	if (-not (Get-Module AzureRm.Profile))
	{
        Import-Module AzureRm.Profile
    }
    $azureRmProfileModuleVersion = (Get-Module AzureRm.Profile).Version
    # refactoring performed in AzureRm.Profile v3.0 or later
	if ($azureRmProfileModuleVersion.Major -ge 3)
	{
        $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
		if (-not $azureRmProfile.Accounts.Count)
		{
            Write-Error "Ensure you have logged in before calling this function."    
        }
    }
	else
	{
        # AzureRm.Profile < v3.0
        $azureRmProfile = [Microsoft.WindowsAzure.Commands.Common.AzureRmProfileProvider]::Instance.Profile
		if (-not $azureRmProfile.Context.Account.Count)
		{
            Write-Error "Ensure you have logged in before calling this function."    
        }
    }
  
    $currentAzureContext = Get-AzureRmContext
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile)
    Write-Debug ("Getting access token for tenant" + $currentAzureContext.Subscription.TenantId)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
	
	return $token.AccessToken
}

function Get-BearerToken
{
	# Format the bearer token for use in header for API call.
	$context = Get-AzureRmContext
	$tokenCache = $context.TokenCache
	$tenantId = $context.Tenant
	$cachedTokens = $tokenCache.ReadItems() `
        | Where-Object { $_.TenantId -eq $tenantId } `
		| Sort-Object -Property ExpiresOn -Descending
	$accessToken = $cachedTokens[0]
	$bearerToken = "Bearer " + $accessToken.AccessToken
	$bearerToken = ('Bearer {0}' -f (Get-AzureRmCachedAccessToken))

	return $bearerToken
}

Write-Host

# Attempt to obtain auth token for Azure API calls
try
{
	Login
	$token = Get-BearerToken
}
catch
{
	Write-Error "There was an error logging into Azure and creating an authentication token. $($_.Exception.Message)"
	Exit 1
}

# Verify the ConfigPath parameter contains the path to an actual file.
if (Test-Path $ConfigPath)
{
	Write-Verbose "ConfigPath path, '$ConfigPath' is valid"
}
else
{
	Write-Error "ConfigPath path, '$ConfigPath' does not exist. Please verify the ConfigPath path and run the command again."
	Exit 1
}


# Make sure there are no spaces in action group short name. Need to figure out how to pass spaces in API call.
# The call fails with spaces, but GUI will allow creation with spaces.
if ($ActionGroupShortName.Contains(" "))
{
	Write-Error "Parameter ActionGroupShortName cannot contain spaces"
}

# Select subscription
try
{
	Select-AzureRmSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
}
catch
{
	Write-Error "Failed to select subscription with error $($_.Exception.Message)"
	Exit 1
}

Write-Host "Verifying parameters..."
# Verify Subscription exists. Probably a moot point since we would have failed to login if this was not valid.
try
{
	Get-AzureRmSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
}
catch
{
	Write-Error $_.Exception.Message
	Exit 1
}

# Verify Resource Group exists. Potential to use ARM templates later to give the option to create as part of toolkit.
try
{
	Get-AzureRmResourceGroup -Name $ResourceGroup -ErrorAction Stop | Out-Null
}
catch
{
	Write-Error "Failed to find resource group. Please verify resource group exists and try again.`r`n Error: $($_.Exception.Message)"
	Exit 1
}

# Verify Workspace. Potential to use ARM templates later to give the option to create as part of toolkit.
try
{
	Get-AzureRmOperationalInsightsIntelligencePacks -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName -ErrorAction Stop | Out-Null
	$workspace = Get-AzureRmOperationalInsightsWorkspace | Where-Object { $_.Name -eq $WorkspaceName; }
}
catch
{
	Write-Error "Failed to find workspace. Please verify workspace exists and try again.`r`n Error: $($_.Exception.Message)"
	Exit 1
}


# Prompt user if no alert email address was provided.
if (!$AlertEmailAddress -and !$ExistingActionGroupName)
{
	$AlertEmailAddress = Read-Host -Prompt "`nEnter the email address to be subscribed for alerts"
}

# Retrieve core monitoring config data from configuration file and convert from JSON to PowerShell object
$alertConfig = (Get-Content $ConfigPath) | ConvertFrom-Json


# API Versions ** under review **
$apiversion = $alertConfig.ApiVersion
if (!$apiversion)
{
	Write-Error "API Version not found in the configuration file. Exiting script."
	Exit 1
}

# Derive an action group name from the workspace name if none is provided
if (!$NewActionGroupName)
{
	$NewActionGroupName = "$($WorkspaceName)-email-ag1"
	Write-Verbose "No action group name defined by user. Action group name will be '$NewActionGroupName'"
}

# Verify Action Group provided by user exists. Potential to use ARM templates later to give the option to create as part of toolkit.
Write-Verbose "Verifying action group if provided and set ActionResourceGroup"
if ($ExistingActionGroupName)
{
	Write-Verbose "User provided existing action group"
	$type = "Microsoft.Insights/ActionGroups"
	$actiongroupFindResult = Get-AzureRmResource -ResourceType $type -Name $ExistingActionGroupName
	
	if ($actiongroupFindResult)
	{
		Write-Verbose "User provided action group found"
		$ActionResourceGroup = $actiongroupFindResult.ResourceGroupName
		$ActionGroupName = $ExistingActionGroupName
	}
	else
	{
		Write-Error "Action group with name '$ExistingActionGroupName' not found in subscription '$SubscriptionId'"
		Exit 1
	}
}
else
{
	Write-Verbose "User did not provide existing action group using NewActionGroupName"
	$ActionResourceGroup = $ResourceGroup
	$ActionGroupName = $NewActionGroupName
	
	# Creates action group to be used for core monitoring alerts
	#TODO: Add error checking
	Write-Host "Creating action group..."
	$actionGroupCreateResult = New-ActionGroup `
		-SubscriptionID $SubscriptionID `
		-ResourceGroup $ResourceGroup `
		-AlertEmailAddress $AlertEmailAddress `
		-ActionGroupName $NewActionGroupName `
		-ActionGroupShortName $ActionGroupShortName
	Write-Host "Action group with name, '$NewActionGroupName' created successfully"
}

##### Update event and perf collections
Write-Host "Configuring event log collections..."
Update-WorkspaceEventCollection -ResourceGroup $ResourceGroup `
	-WorkspaceName $WorkspaceName `
	-EventLogConfig $alertConfig.Events

Write-Host "Configuring performance counter collections..."
Update-WorkspacePerfCollection `
	-Workspace $workspace `
	-PerfCollectionConfig $alertConfig.PerformanceCounters


##### Begin creating alerts

# Loop through alerts in config file and create all necessary components, including saved search, schedule and the alert.
$alertProgressCount = 1
$numAlerts = $alertConfig.Alerts.Count
Write-Host "Beginning creation of $numAlerts alerts..."
foreach ($alert in $alertConfig.Alerts){
	
	# If the alert from the config file has a GUID, use that. Otherwise generate one.
	$alertGuid = $alert.AlertGuid
	if (!$alertGuid)
	{
		$alertGuid = [string]"$(New-Guid)"
	}
	Write-Verbose "AlertGuid: $alertGuid"
	
	$alertDisplayName = $alert.AlertName
	
	Write-Host " -Creating alert $alertProgressCount of $($numAlerts): '$alertDisplayName'"
	
	# Create Saved Searches to be used in Alert configurations
	Write-Verbose "Creating Saved Searches..."
	$savedSearchResult = New-AlertSavedSearch `
		-SubscriptionId $SubscriptionID `
		-ResourceGroup $ResourceGroup `
		-WorkspaceName $WorkspaceName `
		-SavedSearchId $alertGuid `
		-ApiVersion $apiversion `
		-Properties $alert.SavedSearch
	Write-Verbose "Saved Searches created successfully"
	
	# Create Schedules. 
	Write-Verbose "Creating Schedules..."
	$scheduleResult = New-AlertSchedule `
		-SubscriptionId $SubscriptionID `
		-ResourceGroup $ResourceGroup `
		-WorkspaceName $WorkspaceName `
		-SavedSearchId $alertGuid `
		-ScheduleId $alertGuid `
		-BearerToken $token `
		-ApiVersion $apiversion `
		-Properties $alert.Schedule
	Write-Verbose "Schedules created successfully"
	
	# Create alert action
	Write-Verbose "Creating alerts..."
	$actionResult = New-AzureAlert `
		-SubscriptionId $SubscriptionId `
		-ResourceGroup $ResourceGroup `
		-ActionResourceGroup $ActionResourceGroup `
		-WorkspaceName $WorkspaceName `
		-SavedSearchId $alertGuid `
		-ScheduleId $alertGuid `
		-AlertId $alertGuid `
		-ActionGroupName $ActionGroupName `
		-ApiVersion $apiversion `
		-BearerToken $token `
		-Properties $alert.AlertDefinition
	Write-Verbose "Alerts created successfully.."
	
	$alertProgressCount++
}
Write-Host "Alert creation complete..."

Write-Host "Script exiting..."
Write-Host