$PSVersionTable

# name of the forest is test-env

cd C:\Powershell-AD

#Import Active Directory commands
Import-Module ActiveDirectory

$RootDN = "OU=Company XYZ, DC=test-env, DC=local"
$StaffOU = "OU=Staff,$RootDN"

# log file will be used to store any errors that occur in the try-catch section
$LogFile = ".\Logfile.txt"

# Check if CSV file exists
if (!(Test-Path ".\employees.csv")) {
    Write-Error "CSV file not found. Please make sure 'employees.csv' exists."
    exit
}

#Create a new organizational unit for CompanyXYZ
New-ADOrganizationalUnit -Name "Company XYZ" -Path "DC=test-env, DC=local" -ProtectedFromAccidentalDeletion $false

# create organizational units for Staff of the company and clients of the company
New-ADOrganizationalUnit -Name "Staff" -Path $RootDN -ProtectedFromAccidentalDeletion $false

# create departments within the staff to better organize
New-ADOrganizationalUnit -Name "ITDept" -Path $StaffOU -ProtectedFromAccidentalDeletion $false
New-ADOrganizationalUnit -Name "HRDept" -Path $StaffOU -ProtectedFromAccidentalDeletion $false
New-ADOrganizationalUnit -Name "AccountingDept" -Path $StaffOU -ProtectedFromAccidentalDeletion $false

# Create department groups for security purposes
$departments = @("ITDept", "HRDept", "AccountingDept")

foreach ($dept in $departments) {
#put security groups in department paths
    $deptOUPath = "OU=$dept,$StaffOU"
    $groupName = "$dept-Group"

    if (-not (Get-ADGroup -Filter { Name -eq $groupName })) {
        $groupParams = @{
            Name         = $groupName
            GroupScope   = 'Global'
            GroupCategory= 'Security'
            Path         = $deptOUPath
        }
        New-ADGroup @groupParams
        Write-Host "Created group: $groupName in $deptOUPath"
    }
}

# Load employees from CSV
$employees = Import-Csv -Path ".\employees.csv"

foreach ($employee in $employees) {
    try {
        # Set department path
        $departmentOU = "OU=$($employee.Department),$StaffOU"

        # Create user parameters by storing variables in a hash table to reduce repitition
        $userParams = @{
            Name               = "$($employee.FirstName) $($employee.LastName)"
            SamAccountName     = $employee.Username
            UserPrincipalName  = "$($employee.Username)@test-env.local"
            Path               = $departmentOU
            AccountPassword    = (ConvertTo-SecureString "DefaultP@ssword1" -AsPlainText -Force)
            Enabled            = $true
            Title              = $employee.JobTitle
            EmployeeID         = $employee.EmployeeNumber
            Office             = $employee.OfficeLocation
            OfficePhone        = $employee.PhoneNumber
            ErrorAction        = 'Stop'
        }

        # Create new user using parameters 
        New-ADUser @userParams

        # Force password change
        Set-ADUser -Identity $employee.Username -ChangePasswordAtLogon $true

        # Add users to their department group 
        $groupName = "$($employee.Department)-Group"
        Add-ADGroupMember -Identity $groupName -Members $employee.Username -ErrorAction SilentlyContinue

        Write-Host "Added $($employee.Username) to group $groupName"
        Write-Host "Created user: $($employee.Username)"
        Add-Content $LogFile "SUCCESS: Created user: $($employee.Username) at $(Get-Date)"
    }
    catch {
        #states that user was not created and logged into file
        Write-Warning "Failed to create user: $($employee.Username) - $_"
        Add-Content $LogFile "ERROR: $($employee.Username) - $_"
    }
}

# Summary output that will be stored in the log file 
$successCount = (Select-String -Path $LogFile -Pattern "SUCCESS" | Measure-Object).Count
$errorCount = (Select-String -Path $LogFile -Pattern "ERROR" | Measure-Object).Count

# summarizes success or failues to person running the file. 
Write-Host "`n----- Summary -----"
Write-Host "Users Created: $successCount"
Write-Host "Errors: $errorCount"

# test commands 
Get-ADUser -Identity "ypark" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "ITDept-Group" | Select-Object Name, SamAccountName
Get-ADUser -Identity "apatel" -Properties *
