function Get-WDACPolicyRefreshEventFilter {
    <#
    .SYNOPSIS
    Returns a filter to use to get only events that occured since last policy refresh
    
    .DESCRIPTION
    Get-WDACPolicyRefreshEventFilter retrieves the latestMicrosoft-Windows-CodeIntegrity/Operational policy refresh event (id 3099) and generates a string to insert in "FilterXPath" filters to only search for events generated after the latest policy refresh
    
    .EXAMPLE
    Get-WDACPolicyRefreshEventFilter
    
    Looks for the latest policy refresh event and returns a filter string such as " and TimeCreated[@SystemTime >= '2020-10-05T08:11:22.7969367+02:00']"
    #>
    [CmdletBinding()]
    param()

    # Only consider failed audit events that occured after the last CI policy update (event ID 3099)
    $LastPolicyUpdateEvent = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3099 } -MaxEvents 1 -ErrorAction Ignore

    # Sometimes this event will not be present - e.g. if the log rolled since the last update.
    if ($LastPolicyUpdateEvent) {
        $DateTimeAfter = [Xml.XmlConvert]::ToString($LastPolicyUpdateEvent.TimeCreated.ToUniversalTime())

        " and TimeCreated[@SystemTime >= '$DateTimeAfter']"
    } else {
        Write-Verbose "No policy update event was present in the event log. Ignoring the -SinceLastPolicyRefresh switch."
        ''
    }
}

function Get-WDACApplockerScriptMsiEvent {
<#
.SYNOPSIS

Returns script/MSI event log audit/enforcement events in a more human-readable fashion.

.DESCRIPTION

Get-WDACApplockerScriptMsiEvent retrieves and parses Microsoft-Windows-AppLocker/MSI and Script audit and enforcement events into a format that is more human-readable. This function is designed to facilitate regular code integrity policy baselining. Non-PE code that is subject to code integrity enforcement is logged to the Microsoft-Windows-AppLocker/MSI and Script log.

Author: Matthew Graeber
License: BSD 3-Clause

.PARAMETER MaxEvents

Specifies the maximum number of events that Get-WDACCodeIntegrityEvent returns. The default is to return all the events.

.PARAMETER SinceLastPolicyRefresh

Specifies that events should only be returned since the last time the code integrity policy was refreshed. This option is useful for baselining purposes.

.EXAMPLE

Get-WDACApplockerScriptMsiEvent

Return all user-mode code integrity events (audit/enforcement) since the last code intgrity policy refresh.

.EXAMPLE

Get-WDACApplockerScriptMsiEvent -MaxEvents 5

Return the most recent 5 script/MSI code integrity events.

.EXAMPLE

Get-WDACApplockerScriptMsiEvent -SinceLastPolicyRefresh

Return all script/MSI code integrity events since the last code intgrity policy refresh.
#>

    [CmdletBinding()]
    param (
        [Int64]
        $MaxEvents,

        [Switch]
        $SinceLastPolicyRefresh
    )

    $MaxEventArg = @{}

    # Pass -MaxEvents through to Get-WinEvent
    if ($MaxEvents) { $MaxEventArg = @{ MaxEvents = $MaxEvents } }

    $PolicyRefreshFilter = ''

    if ($SinceLastPolicyRefresh) {
        $PolicyRefreshFilter = Get-WDACPolicyRefreshEventFilter
    }

    $Filter = "*[System[(EventID = 8028 or EventID = 8029)$($PolicyRefreshFilter)]]"

    Write-Verbose "XPath Filter: $Filter"

    Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/MSI and Script' -FilterXPath $Filter @MaxEventArg -ErrorAction Ignore | ForEach-Object {
        switch ($_.Id) {
            8028 { $EventType = 'Audit' }
            8029 { $EventType = 'Enforce' }
        }

        $SHA1FileHash = $null

        if ($_.Properties[2].Value.Length -gt 0) {
            $SHA1FileHash = ($_.Properties[2].Value | ForEach-Object { '{0:X2}' -f $_ }) -join ''
        }

        $ObjectArgs = [Ordered] @{
            TimeCreated = $_.TimeCreated
            EventType = $EventType
            FilePath = $_.Properties[1].Value
            SHA1FileHash = $SHA1FileHash
            UserWriteable = $_.Properties[8].Value
        }

        New-Object -TypeName PSObject -Property $ObjectArgs
    }
}

function Get-WDACCodeIntegrityEvent {
<#
.SYNOPSIS

Returns code integrity event log audit/enforcement events in a more human-readable fashion.

.DESCRIPTION

Get-WDACCodeIntegrityEvent retrieves and parses Microsoft-Windows-CodeIntegrity/Operational PE audit and enforcement events into a format that is more human-readable. This function is designed to facilitate regular code integrity policy baselining.

Author: Matthew Graeber
License: BSD 3-Clause

.PARAMETER User

Specifies that only user-mode events should be returned. If neither -User nor -Kernel is specified, user and kernel events are returned.

.PARAMETER Kernel

Specifies that only kernel-mode events should be returned. If neither -User nor -Kernel is specified, user and kernel events are returned.

.PARAMETER Audit

Specifies that only audit events (event ID 3076) should be returned. If neither -Audit nor -Enforce is specified, audit and enforcement events are returned.

.PARAMETER Enforce

Specifies that only enforcement events (event ID 3077) should be returned. If neither -Audit nor -Enforce is specified, audit and enforcement events are returned.

.PARAMETER SinceLastPolicyRefresh

Specifies that events should only be returned since the last time the code integrity policy was refreshed. This option is useful for baselining purposes.

.PARAMETER SignerAndWhqlChecks

Specifies that correlated signer and WHQL events should be collected. When there are many CodeIntegrity events present in the event log, collection of signer and WHQL events can be very time consuming.

.PARAMETER MaxEvents

Specifies the maximum number of events that Get-WDACCodeIntegrityEvent returns. The default is to return all the events.

.EXAMPLE

Get-WDACCodeIntegrityEvent -SinceLastPolicyRefresh

Return all code integrity events (user/kernel/audit/enforcement) since the last code intgrity policy refresh.

.EXAMPLE

Get-WDACCodeIntegrityEvent -User -SinceLastPolicyRefresh

Return all user-mode code integrity events (audit/enforcement) since the last code intgrity policy refresh.

.EXAMPLE

Get-WDACCodeIntegrityEvent -Kernel -MaxEvents 5

Return the most recent 5 kernel mode code integrity events.

.EXAMPLE

Get-WDACCodeIntegrityEvent -Kernel -Enforce

Return all kernel mode enforcement events.
#>

    [CmdletBinding()]
    param (
        [Switch]
        $User,

        [Switch]
        $Kernel,

        [Switch]
        $Audit,

        [Switch]
        $Enforce,

        [Switch]
        $SinceLastPolicyRefresh,

        [Switch]
        $SignerAndWhqlChecks,

        [Int64]
        $MaxEvents
    )

    # If neither -User nor -Kernel are supplied, do not filter based on signing scenario
    # If -User and -Kernel are supplied, do not filter based on signing scenario
    # Only filter in a mutually exclusive scenario.
    $ScenarioFilter = ''

    if ($User -and !$Kernel) {
        # 1 == A user-mode rule triggered
        $ScenarioFilter = " and EventData[Data[@Name='SI Signing Scenario'] = 1]"
    } elseif ($Kernel -and !$User) {
        # 2 == A kernel-mode rule triggered
        $ScenarioFilter = " and EventData[Data[@Name='SI Signing Scenario'] = 0]"
    }

    # If neither -Audit nor -Enforce are supplied, do not filter based on event ID
    # If -Audit and -Enforce are supplied, do not filter based on event ID
    # Only filter in a mutually exclusive scenario.
    $ModeFilter = '(EventID = 3076 or EventID = 3077)'

    if ($Audit -and !$Enforce) {
        # Event ID 3076 == an audit event
        $ModeFilter = "EventID = 3076"
    } elseif ($Enforce -and !$Audit) {
        # Event ID 3077 == an enforcement event
        $ModeFilter = "EventID = 3077"
    }

    $PolicyRefreshFilter = ''

    if ($SinceLastPolicyRefresh) {
        $PolicyRefreshFilter = Get-WDACPolicyRefreshEventFilter
    }

    $Filter = "*[System[$($ModeFilter)$($PolicyRefreshFilter)]$ScenarioFilter]"

    Write-Verbose "XPath Filter: $Filter"

    # File paths are often in the format of device path (e.g. \Device\HarddiskVolumeN\).
    # Get-Partition is used to map the volume number to a partition so that file paths can be normalized.
    $Partitions = Get-Partition

    $PartitionMapping = @{}

    foreach ($Partition in $Partitions) {
        if ($Partition.DriveLetter) {
            $PartitionMapping[$Partition.PartitionNumber.ToString()] = $Partition.DriveLetter
        }
    }

    # This hashtable is used to resolve RequestedSigningLevel and ValidatedSigningLevel fields into human-readable properties
    # For more context around signing levels, Alex Ionescu (@aionescu) has a great resource on them:
    # http://www.alex-ionescu.com/?p=146
    $SigningLevelMapping = @{
        [Byte] 0x0 = 'Unchecked'
        [Byte] 0x1 = 'Unsigned'
        [Byte] 0x2 = 'Enterprise'
        [Byte] 0x3 = 'Custom1'
        [Byte] 0x4 = 'Authenticode'
        [Byte] 0x5 = 'Custom2'
        [Byte] 0x6 = 'Store'
        [Byte] 0x7 = 'Antimalware'
        [Byte] 0x8 = 'Microsoft'
        [Byte] 0x9 = 'Custom4'
        [Byte] 0xA = 'Custom5'
        [Byte] 0xB = 'DynamicCodegen'
        [Byte] 0xC = 'Windows'
        [Byte] 0xD = 'WindowsProtectedProcessLight'
        [Byte] 0xE = 'WindowsTcb'
        [Byte] 0xF = 'Custom6'
    }

    $MaxEventArg = @{}

    # Pass -MaxEvents through to Get-WinEvent
    if ($MaxEvents) { $MaxEventArg = @{ MaxEvents = $MaxEvents } }

    Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -FilterXPath $Filter @MaxEventArg -ErrorAction Ignore | ForEach-Object {
        if ($_.Version -lt 5) {
            Write-Warning "Get-WDACCodeIntegrityEvent does not support event version $($_.Version). Version 5+ is supported. Ensure you are running Windows 1903+."
        }

        switch ($_.Id) {
            3076 { $EventType = 'Audit' }
            3077 { $EventType = 'Enforce' }
            default {
                $EventType = $null
                Write-Warning "Unsupported event type: $($_.Id)"
            }
        }

        $WHQLFailed = $null

        $CIEventDateTimeAfter = [Xml.XmlConvert]::ToString($_.TimeCreated.ToUniversalTime())
        $CIEventDateTimeBefore = [Xml.XmlConvert]::ToString($_.TimeCreated.ToUniversalTime().AddSeconds(1))

        if ($SignerAndWhqlChecks) {
            $WHQLFailed = $False

            # A correlated 3082 event indicates that WHQL verification failed
            $WHQLEvent = Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -FilterXPath "*[System[EventID = 3082 and Correlation[@ActivityID = '$($_.ActivityId.Guid)'] and TimeCreated[@SystemTime >= '$CIEventDateTimeAfter'] and TimeCreated[@SystemTime < '$CIEventDateTimeBefore']]]" -ErrorAction Ignore

            if ($WHQLEvent) { $WHQLFailed = $True }
        }

        $ResolvedSigners = $null

        if ($SignerAndWhqlChecks) {
            # Retrieve correlated signer info (event ID 3089)
            # Note: there may be more than one correlated signer event in the case of the file having multiple signers.
            $SignerInfo = Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -FilterXPath "*[System[EventID = 3089 and Correlation[@ActivityID = '$($_.ActivityId.Guid)'] and TimeCreated[@SystemTime >= '$CIEventDateTimeAfter'] and TimeCreated[@SystemTime < '$CIEventDateTimeBefore']]]" @MaxEventArg -ErrorAction Ignore

            $ResolvedSigners = $SignerInfo | ForEach-Object {
                $SignatureTypeVal = $_.Properties[6].Value

                # Note: these signature type mappings were determined based on inference.
                switch ($SignatureTypeVal) {
                    0 { $SignatureType = 'Hash' }
                    1 { $SignatureType = 'Authenticode' }
                    4 { $SignatureType = 'Catalog' }
                    default {
                        $SignatureType = 'Unknown'
                        Write-Warning "Unknown signature type value: $SignatureTypeVal. Investigate what this might correspond to and update this function accordingly."
                    }
                }

                $SignerProperties = [Ordered] @{
                    SignatureIndex = $_.Properties[1].Value
                    PageHash = $_.Properties[5].Value
                    SignatureType = $SignatureType
                    ValidatedSigningLevel = $SigningLevelMapping[$_.Properties[7].Value]
                    NotValidBefore = $_.Properties[11].Value
                    NotValidAfter = $_.Properties[12].Value
                    PublisherName = $_.Properties[14].Value
                    IssuerName = $_.Properties[16].Value
                    PublisherTBSHash = (($_.Properties[18].Value | ForEach-Object { '{0:X2}' -f $_ }) -join '')
                    IssuerTBSHash = (($_.Properties[20].Value | ForEach-Object { '{0:X2}' -f $_ }) -join '')
                }

                New-Object -TypeName PSObject -Property $SignerProperties
            }
        }

        $SigningScenarioVal = $_.Properties[16].Value

        switch ($SigningScenarioVal) {
            0 { $Scenario = 'Driver' }
            1 { $Scenario = 'UserMode' }
            default {
                $Scenario = 'Unknown'
                Write-Warning "Unknown signing scenario value: $SigningScenarioVal. Investigate what this might correspond to and update this function accordingly."
            }
        }

        $FilePath = $_.Properties[1].Value

        $ResolvedFilePath = $null
        # Make a best effort to resolve the device path to a normal path.
        if ($FilePath -match '(?<Prefix>^\\Device\\HarddiskVolume(?<VolumeNumber>\d)\\)') {
            $ResolvedFilePath = $FilePath.Replace($Matches['Prefix'], "$($PartitionMapping[$Matches['VolumeNumber']]):\")
        } elseif ($FilePath.ToLower().StartsWith('system32')) {
            $ResolvedFilePath = "$($Env:windir)\System32$($FilePath.Substring(8))"
        }

        # If all else fails regarding path resolution, show a warning.
        if ($ResolvedFilePath -and !(Test-Path -Path $ResolvedFilePath)) {
            Write-Warning "The following file path was either not resolved properly or was not present on disk: $ResolvedFilePath"
        }

        $SHA1FileHash = $null

        if ($_.Properties[11].Value -eq 20) {
            $SHA1FileHash = ($_.Properties[12].Value | ForEach-Object { '{0:X2}' -f $_ }) -join ''
        }

        $CIEventProperties = [Ordered] @{
            TimeCreated = $_.TimeCreated
            EventType = $EventType
            SigningScenario = $Scenario
            FilePath = $FilePath
            ResolvedFilePath = $ResolvedFilePath
            SHA1FileHash = $SHA1FileHash
            ProcessID = $_.ProcessId
            ProcessName = $_.Properties[3].Value
            RequestedSigningLevel = $SigningLevelMapping[$_.Properties[4].Value]
            ValidatedSigningLevel = $SigningLevelMapping[$_.Properties[5].Value]
            PolicyName = $_.Properties[18].Value
            PolicyID = $_.Properties[20].Value
            PolicyGUID = $_.Properties[32].Value.Guid.ToUpper()
            OriginalFileName = $_.Properties[24].Value
            InternalName = $_.Properties[26].Value
            FileDescription = $_.Properties[28].Value
            ProductName = $_.Properties[30].Value
            FileVersion = $_.Properties[31].Value
            UserWriteable = $_.Properties[33].Value
            FailedWHQL = $WHQLFailed
            SignerInfo = $ResolvedSigners
        }

        New-Object -TypeName PSObject -Property $CIEventProperties
    }
}
