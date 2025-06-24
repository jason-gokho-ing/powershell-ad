$PSVersionTable

# name of the forest is test-env

cd C:\Powershell-AD

#Import Active Directory commands
Import-Module ActiveDirectory


$RootDN = "OU=Company XYZ, DC=test-env, DC=local"
$StaffOU = "OU=Staff,$RootDN"

# log file will be used to store any errors that occur in the try-catch section
$LogFile = ".\Logfile.txt"


#Create a new organizational unit for CompanyXYZ
New-ADOrganizationalUnit -Name "Company XYZ" -Path "DC=test-env, DC=local" -ProtectedFromAccidentalDeletion $false

# create organizational units for Staff of the company and clients of the company
New-ADOrganizationalUnit -Name "Staff" -Path $RootDN -ProtectedFromAccidentalDeletion $false


# create departments within the staff to better organize
New-ADOrganizationalUnit -Name "IT" -Path $StaffOU -ProtectedFromAccidentalDeletion $false
New-ADOrganizationalUnit -Name "HR" -Path $StaffOU -ProtectedFromAccidentalDeletion $false
New-ADOrganizationalUnit -Name "Accounting" -Path $StaffOU -ProtectedFromAccidentalDeletion $false

# Create department groups for security purposes
$departments = @("IT-Group", "HR-Group", "Accounting-Group")

foreach ($dept in $departments) {
    $groupExists = Get-ADGroup -Filter { Name -eq $dept }

    if (-not $groupExists) {
        # each group will be Global and categorized as Security
        New-ADGroup -Name $dept -GroupScope Global -GroupCategory Security -Path $StaffOU
        Write-Host "Created group: $dept"
    }
}


# Load employees from CSV
$employees = Import-Csv -Path ".\employees.csv"


foreach ($employee in $employees) {
    try {
        # Set department path
        $departmentOU = "OU=$($employee.Department),$StaffOU"

        # Create user
        New-ADUser `
            -Name "$($employee.FirstName) $($employee.LastName)" `
            -SamAccountName $employee.Username `
            -UserPrincipalName "$($employee.Username)@test-env.local" `
            -Path $departmentOU `
            -AccountPassword (ConvertTo-SecureString "DefaultP@ssword1" -AsPlainText -Force) `
            -Enabled $true `
            -Title $employee.JobTitle `
            -EmployeeID $employee.EmployeeNumber `
            -Office $employee.OfficeLocation `
            -OfficePhone $employee.PhoneNumber `
            -ErrorAction Stop

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


# test commands 
Get-ADUser -Identity "ypark" | Select-Object Name, SamAccountName

Get-ADGroupMember -Identity "IT-Group" | Select-Object Name, SamAccountName

Get-AdUser -Identity "apatel" -Properties *