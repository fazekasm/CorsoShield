# Pure helpers: no elevation, registry/file changes or credential access.
function New-CorsoInstallAcl {
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $adminSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $systemSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $usersSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $acl.SetOwner($adminSid)
    foreach ($entry in @(@($adminSid,'FullControl'),@($systemSid,'FullControl'),@($usersSid,'ReadAndExecute'))) {
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($entry[0],$entry[1],'ContainerInherit,ObjectInherit','None','Allow')
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}
function Test-CorsoLaunchIdentity([string]$ExpectedSid,[string]$ActualSid) {
    if ($ExpectedSid -and $ExpectedSid -ne $ActualSid) { throw 'A different administrator account was supplied. Sign in as the account whose settings/baselines you intend to manage; Corso will not silently operate on another user profile.' }
}
