# Alert ToolKit
1. [Overview](#overview)
1. [Prerequisites](#prerequisites)
1. [Deployment Steps](#deployment-steps)
1. [Script Help](#script-help)
1. [Alert Components](#alert-components)
1. [Alert Configuration File](#alert-configuration-file)
   - [Creating a custom alert](#creating-a-custom-alert)
   - [Creating a new GUID](#creating-a-new-guid)
   - [Converting KQL to Json](#converting-kql-to-json)
1. [References](#references)


## Overview
The Alert Toolkit automates the deployment of an example set of log alerts to Azure Monitor Log Analytics. The toolkit consists of configuration file containing log alert definitions and a script that deploys the alerts.

**NOTE!** The Alert Toolkit now uses the new scheduledQueryRules API. If you need a copy of the toolkit that works with the old API please use the release linked below. If your workspace is using the new API you can use the latest code from the master branch. Any workspaces created before June 1st 2019 will be using the old API unless you migrated to the new API. For more information on the difference between the two APIs, please [refer here](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-log-api-switch#benefits-of-switching-to-new-azure-api).

**Alert Toolkit for Legacy Log Alerts API**
https://github.com/microsoft/manageability-toolkits/releases/tag/v1.0

##Prerequisites
- [Azure PowerShell module installed (Az, not AzureRm) - Version 2.4.0+](https://docs.microsoft.com/en-us/powershell/azure/install-az-ps)
- Log Analytics workspace created
- User running the toolkit will need Contributor role on the resource group and workspace

## Deployment Steps
1. Download the Alert Toolkit contents to your local system
1. Navigate to the script directory
1. Run the PowerShell script, **New-CoreAlerts.ps1**, with desired parameters. Minimum suggested parameters shown in the example below.
``` powershell
# Run Alert Toolkit with email specified.
.\New-CoreAlerts.ps1 `
-SubscriptionID "<subscriptionId>" `
-WorkspaceName "<Log Analytics Workspace Name>" `
-ResourceGroup "<Log Analytics Workspace resource group name>" `
-Location '<Location of workspace and resource group>' `
-AlertEmailAddress "<email address>"
```
**Sample Output:**

![Sample Output With Parameters](/docs/images/sampleOutputWithParams.png)
4. Alternatively you can run the script with no parameters and you will be prompted for the required parameters.
``` powershell
# Run Alert Toolkit with no parameters
.\New-CoreAlerts.ps1
```
**Sample Output:**

![Sample output with no parameters](/docs/images/sampleOutputNoParams.png)

5. The toolkit can also use an existing action group.

``` powershell
# Run Alert Toolkit with an existing action group specified.
.\New-CoreAlerts.ps1 `
-SubscriptionID "<subscriptionId>" `
-WorkspaceName "<Log Analytics Workspace Name>" `
-ResourceGroup "<Log Analytics Workspace resource group name>" `
-Location '<Location of workspace and resource group>' `
-ExistingActionGroupName '<Name of existing action group>'
```

6. Lastly, the toolkit can also be used to deploy the alerts based on the alert types specified in the configuration file.

``` powershell
# Run Alert Toolkit with an existing action group specified.
.\New-CoreAlerts.ps1 `
-SubscriptionID "<subscriptionId>" `
-WorkspaceName "<Log Analytics Workspace Name>" `
-ResourceGroup "<Log Analytics Workspace resource group name>" `
-Location '<Location of workspace and resource group>' `
-AlertTypes '<Required Alert Types like SQL,HP>'
```

**Sample Output:**
![Sample output with existing action group](/docs/images/sampleOutputExistingActionGroup.png)

7. Once the script completes you will see the alerts in the Azure Portal -> Log Analytics-> Alerts

![Alerts in Azure Portal](/docs/images/portalExample.png)

## Script Help
The New-CoreAlerts script supports PowerShell's Get-Help command. To get the most up-to-date information please run the following from within the script directory.

``` powershell
PS C:\Demo> Get-Help .\New-CoreAlerts.ps1 -Full
```
</br>
At the time of this writing:

```
	.SYNOPSIS
		The Alert Toolkit automates the deployment of an example set of log alerts to Azure Monitor Log Analytics.
	.DESCRIPTION
		The Alert Toolkit automates the deployment of an example set of log alerts to Azure Monitor Log Analytics.
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
	.Parameter AlertTypes
		Specifies the type(s) of alerts to be deployed.
	.Parameter ConfigPath
		Specifies the path to the JSON file containing the alert configurations. Default is '.\DefaultAlertConfig.json'.
	.EXAMPLE 
	   .\New-CoreAlerts.ps1 -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -WorkspaceName 'alertsWorkspace' -ResourceGroup 'alertsRG' -Location 'East US'
	   
	   This command will run the Alert Toolkit script with the provided parameters.
	   
	.EXAMPLE
	   .\New-CoreAlerts.ps1
	   
	   This command will run the Alert Toolkit script and prompt the user for required parameters.
	   
	.EXAMPLE 
	   .\New-CoreAlerts.ps1 -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -ExistingActionGroupName 'useractiongroupname' -WorkspaceName 'alertsWorkspace' -ResourceGroup 'alertsRG' -Location 'East US' 
	   
	   This command will run the Alert Toolkit script with the provided parameters, adding the existing action group named 'useractiongroupname' to all alerts created by the toolkit.
	   
	.EXAMPLE
		.\New-CoreAlerts.ps1 -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -WorkspaceName 'alertsWorkspace' -ResourceGroup 'alertsRG' -Location 'East US' -AlertTypes "Core,SQL"

		This command will run the Alert Toolkit script with the provided parameters, deploying only alerts that are tagged with 'Core' or 'SQL'
		
	.LINK
	https://github.com/Microsoft/manageability-toolkits
	
	
	.Notes
		NAME:     New-CoreAlerts
		AUTHOR(s): Arun Kumar Rajendra <arunkra@microsoft.com>, Matt Carlson <macarlso@microsoft.com>
		LASTEDIT: 02/04/2019
		KEYWORDS: OMS, Log Analytics, Alerts, Core Alerts
```

## Alert Components
The toolkit automates the creation of alerts by creating several different resources and associating them to one another.

**Action Group:**
The action group contains any number of actions that should happen once the alert fires. This could include sending an email or calling a webhook. The Alert Toolkit currently supports just a single email unless an existing action group is provided.

**Saved Search**
The saved search is where the alert query is defined. When the query returns results over a given time period, the alert is fired.

**Schedule**
A saved search can have one or more schedules. The schedule defines how often the search is run and the time interval over which the criteria is identified.

**Alert Action**
Finally, the toolkit creates an alert action. This is associated with the **Saved Search**, **Schedule** and **Action Group** to create the final alert.

More information on how to configure alerts using the REST API can be found here:
https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-api-alerts

## Alert Configuration File
The alert configuration file, **DefaultAlertConfig.json**, contains the alert definitions for Alerts included in the Alert Toolkit. Alerts can be added or removed from the configuration file before running the script.

### Creating a custom alert
A custom alert can be added to the toolkit by modifying the configuration file before running the deployment script. Existing alerts can be used an example, but the alert should have the following elements. More detailed information about what is required by the Log Analytics REST API can be found [here](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/api-alert).

**AlertName** - Name of the alert. To be displayed in script output.
**AlertGuid** - Unique GUID for the alert in your subscription. Click here for more information on [Creating a new GUID](#creating-a-new-guid).

**SavedSearch**  - The SavedSearch element contains the JSON payload required to create saved search. This is the basis of a log analytics alert. This includes such information as the category and display name, but most importantly the query that will be used to define the criteria for an Alert.

- Category - The category for the saved search. This can be used to group alerts together or filter them in the Azure Portal.
- DisplayName - The display name for the saved search.
- Query - The Log Analytics query for the saved search. This must be properly escaped Json for special characters like quotes. Click here for more information on [Converting KQL to Json](#converting-kql-to-json)
- Version - The API version being used. Currently, this should always be set to 1.

**Schedule** - This section contains the Json payload required to create the alert schedule.
- Interval - How often the search is run. Measured in minutes.
- QueryTimeSpan - The time interval over which the criteria is evaluated. Must be equal to or greater than Interval. Measured in minutes.
- Active - Need to be set to **true**.

**AlertDefinition** - This section contains the configuration for the alert itself.
- Name - The name displayed for the alert.
- Description - A description of the alert.
- Version - The API version being used. Currently, this should always be set to 1.
- Severity - Log Analytics allows you to classify your alerts into categories, to allow easier management and triage. The Alert severity defined is: informational, warning, and critical.
- Type - This should be set to **Alert**.
- Threshold - Criteria for when the action is run.
   - Operator - Operator for the threshold comparison. 
gt = Greater Than 
lt = Less Than
   - Value - Value for the threshold.
- AzNsNotification - This section contains the configuration for what action is taken when the alert fires.
   - GroupIds - Should be set to _/subscriptions/subscrname/resourcegroups/resourcegrp/providers/microsoft.insights/actiongroups/samplecoreactiongroup_
   - CustomEmailSubject - The custom email subject text if the default email notification is used.

**Example:**
``` json
{
      "AlertName": "NTFS - File System Corrupt",
      "AlertGuid": "bb8527b1-6152-4d28-be04-c3d81cf98407",
      "Tags": [
        "Core"
      ],
      "SavedSearch": {
        "Category": "Core",
        "DisplayName": "Alert - NTFS - File System Corrupt",
        "Query": "Event | where EventLog == \"System\" and Source == \"DISK\" or Source == \"Ntfs\" and EventID == 55 | project Computer, TimeGenerated, AlertType_s = \"NTFS - File System Corrupt\", Severity = 4, SeverityName_s = \"WARNING\", AffectedCI_s = Computer, AlertTitle_s = strcat(Computer, \": NTFS - File System Corrupt\"), AlertDetails_s = strcat(\"Event Description:\\r\\n\", RenderedDescription)",
        "Version": "1"
      },
      "Schedule": {
        "Interval": 30,
        "QueryTimeSpan": 30,
        "Active": "true"
      },
      "AlertDefinition": {
        "Name": "NTFS - File System Corrupt",
        "Description": "Core monitoring alert for monitoring disk",
        "Version": "1",
        "Severity": "critical",
        "Type": "Alert",
        "Threshold": {
          "Operator": "gt",
          "Value": 0
        },
        "AzNsNotification": {
          "GroupIds": [
            "/subscriptions/subscrname/resourcegroups/resourcegrp/providers/microsoft.insights/actiongroups/samplecoreactiongroup"
          ],
          "CustomEmailSubject": "Alert - NTFS - File System Corrupt"
        }
      }
    }
```

### Creating a new GUID
Run the following in a PowerShell console to generate a new GUID.
``` powershell
New-Guid
````

![Sample GUID creation output](/docs/images/sampleOutputGuid2.png)

### Converting KQL to JSON
To convert an existing Log Analytics query to JSON you can use the folloiwng method in PowerShell.

``` powershell
$kql = '[insert KQL query text here, new lines and all]'
($kql.Replace("`r","").Replace("`n","")) | ConvertTo-Json
```

Here’s an example with the NTFS Alert from the toolkit:

**KQL:**
``` kql
Event
| where EventLog == "System" and Source == "DISK" or Source == "Ntfs" and EventID == 55
| project Computer, TimeGenerated, AlertType_s = "NTFS - File System Corrupt", Severity = 4, SeverityName_s = "WARNING", AffectedCI_s = Computer, AlertTitle_s = strcat(Computer, ": NTFS - File System Corrupt"), AlertDetails_s = strcat("Event Description:\r\n", RenderedDescription)
```

**Output:**
``` powershell
PS C:\> $kql = 'Event
>> | where EventLog == "System" and Source == "DISK" or Source == "Ntfs" and EventID == 55
>> | project Computer, TimeGenerated, AlertType_s = "NTFS - File System Corrupt", Severity = 4, SeverityName_s = "WARNING", AffectedCI_s = Computer, AlertTitle_s = strcat(Computer, ": NTFS - File System Corrupt"), AlertDetails_s = strcat("Event Description:\r\n", RenderedDescription)'

PS C:\> ($kql.Replace("`r","").Replace("`n","")) | ConvertTo-Json
"Event| where EventLog == \"System\" and Source == \"DISK\" or Source == \"Ntfs\" and EventID == 55| project Computer, TimeGenerated, AlertType_s = \"NTFS - File System Corrupt\", Severity = 4, SeverityName_s = \"WARNING\", AffectedCI_s = Computer, AlertTitle_s = strcat(Computer, \": NTFS - File System Corrupt\"), AlertDetails_s = strcat(\"Event Description:\\r\\n\", RenderedDescription)"
```

![Sample output for KQL to JSON conversion](/docs/images/sampleOutputKqlConversion.png)
 
The downside to this approach is that ConvertTo-Json replaces special characters like ‘>’ with their Unicode representation like ‘\u003e’. The good news is that ConvertFrom-Json, which the script uses, will convert it back. Alternatively, you can replace it yourself as long as it’s not a character that needs to be escaped. We’ve done this with some of the alerts in the default toolkit because it looks cleaner. It’s not strictly necessary though.

## References
**Create and manage alert rules in Log Analytics with REST API**
https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-api-alerts


## Contributing
 [Contribution guidelines for this project](/docs/CONTRIBUTING.md)