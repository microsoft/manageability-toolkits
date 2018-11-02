# Core Monitoring Tool Kit
1. [Overview](#overview)
1. [Prerequisites](#prerequisites)
1. [Deployment Steps](#deployment-steps)
1. [Alert Components](#alert-components)
1. [Alert Configuration File](#alert-configuration-file)
1. [Script Help](#script-help)
1. [References](#references)
1. [Contributing](#contributing)


## Overview
The Core Monitoring Toolkit automates the deployment of an example set of log alerts to Azure Monitor Log Analytics. The toolkit consists of configuration file containing log alert definitions and a script that deploys the alerts.

## Prerequisites
- [AzureRm PowerShell Module installed](https://docs.microsoft.com/en-us/powershell/azure/install-azurerm-ps?view=azurermps-5.7.0)
- Log Analytics workspace created
- User running the toolkit will need Contributor role on the resource group and workspace

## Deployment Steps
1. Download the core monitoring toolkit contents to your local system
1. Navigate to the script directory
1. Run the PowerShell script, **New-CoreAlerts.ps1**, with desired parameters. Minimum suggested parameters shown in the example below.
``` powershell
# Run core monitoring toolkit with email specified.
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
# Run core monitoring toolkit with no parameters
.\New-CoreAlerts.ps1
```
**Sample Output:**

![Sample output with no parameters](/docs/images/sampleOutputNoParams.png)

5. Lastly, the toolkit can use an existing action group.

``` powershell
# Run core monitoring toolkit with an existing action group specified.
.\New-CoreAlerts.ps1 `
-SubscriptionID "<subscriptionId>" `
-WorkspaceName "<Log Analytics Workspace Name>" `
-ResourceGroup "<Log Analytics Workspace resource group name>" `
-Location '<Location of workspace and resource group>' `
-ExistingActionGroupName '<Name of existing action group>'
```

**Sample Output:**
![Sample output with existing action group](/docs/images/sampleOutputExistingActionGroup.png)

6. Once the script completes you will see the alerts in the Azure Portal -> Log Analytics-> Alerts

![Alerts in Azure Portal](/docs/images/portalExample.png)

## Alert Components
The toolkit automates the creation of alerts by creating several different resources and associating them to one another.

**Action Group:**
The action group contains any number of actions that should happen once the alert fires. This could include sending an email or calling a webhook. The Core Monitoring toolkit currently supports just a single email. Additional actions can be added later.

**Saved Search**
The saved search is where the alert query is defined. When the query returns results over a given time period, the alert is fired.

**Schedule**
A saved search can have one or more schedules. The schedule defines how often the search is run and the time interval over which the criteria is identified.

**Alert Action**
Finally, the toolkit creates an alert action. This is associated with the **Saved Search**, **Schedule** and **Action Group** to create the final alert.

More information on how to configure alerts using the REST API can be found here:
https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-api-alerts

## Alert Configuration File
The alert configuration file, **Configure.xml**, contains the alert definitions for Alerts included in the Core Monitoring Toolkit. Alerts can be added or removed from the configuration file before running the script.

Each **Alert** element in the configuration file contains a **Search** and **Email** element.

The **Search** element contains the JSON payload required to create saved search. This is the basis of a log analytics alert. This includes such information as the category and display name, but most importantly the query that will be used to define the criteria for an Alert.

The **Email** element contains the JSON payload required to create the alert and tie it to an action group.

## Script Help
The New-CoreAlerts script supports PowerShell's Get-Help command. To get the most up-to-date information please run the following from within the script directory.

``` powershell
PS C:\Demo> Get-Help .\New-CoreAlerts.ps1 -Full
```
</br>
At the time of this writing:

```
	.SYNOPSIS
		The Core Monitoring Toolkit automates the deployment of an example set of log alerts to Azure Monitor Log Analytics.

	.DESCRIPTION
		The Core Monitoring Toolkit automates the deployment of an example set of log alerts to Azure Monitor Log Analytics.
		The toolkit consists of configuration file containing log alert definitions and a script that deploys the alerts.

	.Parameter SubscriptionID
		Specifies the Azure Subscription ID for the workspace where the alerts will be created.
	.Parameter WorkspaceName
		Specifies the name for the workspace where the alerts will be created.
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
```

## References
**Create and manage alert rules in Log Analytics with REST API**
https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-api-alerts


## Contributing
 [Contribution guidelines for this project](docs/CONTRIBUTING.md)