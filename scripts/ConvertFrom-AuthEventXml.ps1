# Pure conversion helper: no log access, file writes, or policy changes.
# Kept separate so synthetic XML fixtures can exercise the actual parser.
function ConvertFrom-AuthEventXml {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Xml)

    $document = New-Object System.Xml.XmlDocument
    $document.XmlResolver = $null
    $document.LoadXml($Xml)
    $ns = [System.Xml.XmlNamespaceManager]::new($document.NameTable)
    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $system = $document.SelectSingleNode('/e:Event/e:System', $ns)
    if (-not $system) { throw 'The XML is not a Windows event with a System element.' }

    $eventId = [int]$system.SelectSingleNode('e:EventID', $ns).InnerText
    $eventMeanings = @{
        4624 = 'Successful logon'; 4625 = 'Failed logon'
        4720 = 'User account created'; 4740 = 'User account locked out'
    }
    if (-not $eventMeanings.ContainsKey($eventId)) {
        throw "Unsupported event ID: $eventId"
    }

    # Named fields tolerate changes in order and optional fields across versions.
    $data = @{}
    foreach ($node in $document.SelectNodes('/e:Event/e:EventData/e:Data', $ns)) {
        $data[$node.GetAttribute('Name')] = $node.InnerText
    }
    $logonTypes = @{
        '2' = 'Interactive'; '3' = 'Network'; '4' = 'Batch'; '5' = 'Service'
        '7' = 'Unlock'; '8' = 'Network cleartext'; '9' = 'New credentials'
        '10' = 'Remote interactive'; '11' = 'Cached interactive'
        '12' = 'Cached remote interactive'; '13' = 'Cached unlock'
    }
    $statusMeanings = @{
        '0x0' = 'No additional error information'
        '0xC0000064' = 'User name does not exist'
        '0xC000006A' = 'Incorrect password'
        '0xC000006D' = 'Invalid user name or authentication information'
        '0xC0000072' = 'Account disabled'
        '0xC0000234' = 'Account locked out'
        '0xC000015B' = 'Requested logon type is not granted'
    }
    $logonType = $data['LogonType']
    $logonMeaning = if (-not $logonType) { 'Not present' }
        elseif ($logonTypes.ContainsKey($logonType)) { $logonTypes[$logonType] }
        else { 'Unmapped; review Microsoft documentation' }

    # Keep BOTH original codes. SubStatus supplements Status; it does not replace it.
    $status = $data['Status']
    $subStatus = $data['SubStatus']
    $statusMeaning = if (-not $status) { 'Not present' }
        elseif ($statusMeanings.ContainsKey($status)) { $statusMeanings[$status] }
        else { 'Unmapped; review Microsoft documentation' }
    $subStatusMeaning = if (-not $subStatus) { 'Not present' }
        elseif ($statusMeanings.ContainsKey($subStatus)) { $statusMeanings[$subStatus] }
        else { 'Unmapped; review Microsoft documentation' }

    $timestamp = $system.SelectSingleNode('e:TimeCreated', $ns).GetAttribute('SystemTime')
    $utc = [DateTimeOffset]::Parse($timestamp, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
    $targetSid = $data['TargetUserSid']
    if (-not $targetSid) { $targetSid = $data['TargetSid'] } # 4720 and 4740
    $targetDomain = $data['TargetDomainName']
    $callerComputer = $data['CallerComputerName']
    $callerField = if ($callerComputer) { 'CallerComputerName' } else { $null }
    if ($eventId -eq 4740) {
        # Microsoft's documented 4740 v0 XML puts Caller Computer Name in
        # TargetDomainName. Do not mislabel that value as the account's domain.
        $targetDomain = $null
        if (-not $callerComputer) {
            $callerComputer = $data['TargetDomainName']
            $callerField = 'TargetDomainName (4740 schema)'
        }
    }

    [pscustomobject][ordered]@{
        TimeCreatedUtc = $utc.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
        RecordId = [long]$system.SelectSingleNode('e:EventRecordID', $ns).InnerText
        EventId = $eventId
        EventMeaning = $eventMeanings[$eventId]
        EventVersion = $system.SelectSingleNode('e:Version', $ns).InnerText
        Computer = $system.SelectSingleNode('e:Computer', $ns).InnerText
        Channel = $system.SelectSingleNode('e:Channel', $ns).InnerText
        Provider = $system.SelectSingleNode('e:Provider', $ns).GetAttribute('Name')
        SubjectUser = $data['SubjectUserName']
        SubjectDomain = $data['SubjectDomainName']
        SubjectSid = $data['SubjectUserSid']
        SubjectLogonId = $data['SubjectLogonId']
        TargetUser = $data['TargetUserName']
        TargetDomain = $targetDomain
        TargetDomainRaw = $data['TargetDomainName']
        TargetSid = $targetSid
        TargetLogonId = $data['TargetLogonId']
        LogonTypeCode = $logonType
        LogonTypeMeaning = $logonMeaning
        AuthenticationPackage = $data['AuthenticationPackageName']
        Workstation = $data['WorkstationName']
        SourceIpAddress = $data['IpAddress']
        SourcePort = $data['IpPort']
        ProcessId = $data['ProcessId']
        ProcessName = $data['ProcessName']
        CallerComputer = $callerComputer
        CallerComputerSourceField = $callerField
        StatusCode = $status
        StatusMeaning = $statusMeaning
        SubStatusCode = $subStatus
        SubStatusMeaning = $subStatusMeaning
        FailureReasonRaw = $data['FailureReason']
    }
}
