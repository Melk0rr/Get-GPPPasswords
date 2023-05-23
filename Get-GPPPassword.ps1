function Get-GPPPassword {
  <#
  .SYNOPSIS
    Script model

  .NOTES
    Name: Get-ScriptModel
    Author: JL
    Version: 1.0
    LastUpdated: 2023-May-05

  .EXAMPLE

  #>

  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
  [CmdletBinding()]
  param(
    [Parameter(
      Mandatory = $false,
      ValueFromPipeline = $false,
      ValueFromPipelineByPropertyName = $false
    )]
    [ValidateNotNullOrEmpty()]
    [string]  $Domain = $env:USERDNSDOMAIN,

    [Parameter(
      Mandatory = $false,
      ValueFromPipeline = $false,
      ValueFromPipelineByPropertyName = $false
    )]
    [ValidateNotNullOrEmpty()]
    [array]  $Files,

    [Parameter(
      Mandatory = $false,
      ValueFromPipeline = $false,
      ValueFromPipelineByPropertyName = $false
    )]
    [ValidateNotNullOrEmpty()]
    [string]  $Password
  )

  # Helper function that decrypts a CPassword
  function Get-DecryptedCPassword {
    [CmdletBinding()]
    Param (
      [string] $cPassword
    )
  
    try {
      #Append appropriate padding based on string length
      $pad = "=" * (4 - ($cPassword.length % 4))
      $convertedBase64 = [Convert]::FromBase64String($cPassword + $pad)
  
      #Create a new AES .NET Crypto Object
      $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider

      # 32-byte AES key used by MS : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
      [byte[]] $aesKey = @(0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
        0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b)
  
      #Set Initialization Vector to all nulls to prevent dynamic generation of IV value
      $aes.IV = New-Object Byte[]($aes.IV.length)
      $aes.Key = $aesKey
      
      $decryptor = $aes.CreateDecryptor()
      [byte[]] $res = $decryptor.TransformFinalBlock($convertedBase64, 0, $convertedBase64.length)
  
      return [System.Text.UnicodeEncoding]::Unicode.GetString($res)
    }
  
    catch { Write-Error "Error while decrypting cpassword: $_" }
  }

  # Helper function to retreive GPO GUID from file
  function Get-GPOGUIDFromFile {
    [CmdletBinding()]
    Param (
      $file
    )
    return [regex]::Matches($file.FullName, '{([-0-9A-F]+?)}').Value.Trim("{", "}")
  }

  # Helper function to parse cpassword from gpp xml file
  function Get-PasswordFromXML {
    [CmdletBinding()]
    Param (
      $file
    )

    try {
      [xml] $xml = Get-Content $file

      # Checks if the file contains a cpassword
      $containsCPassword = $xml.innerxml -match "cpassword"
      $containsAutoLogon = ($xml.innerxml -match "DefaultPassword") -and ($xml.innerxml -match "DefaultUserName")

      if (!$containsCPassword -and !$containsAutoLogon) {
        return
      }

      # Retreive GPO if GroupPolicy module is present
      $GPOGUID = Get-GPOGUIDFromFile $file
      $GPOName = $GPOGUID
      if ($HASGROUPPOLICY) {
        $GPO = Get-GPO -GUID $GPOGUID
        $GPOName = $GPO.displayName
      }

      $res = @()

      # Helper function to address common instructions regardless of a cpassword or autologon password
      function Get-CommonPasswordData {
        Param (
          $node
        )

        if ($passwordType -ne "CPassword") {
          $decryptedPwd = $password
        }

        try {
          $changed = $node.ParentNode.changed
        }
        catch {
          Write-Verbose "Unable to retrieve changed date for '$file'"
        }

        try {
          $nodeName = $node.ParentNode.ParentNode.LocalName
        }
        catch {
          Write-Verbose "Unable to retrieve localName for '$file'"
        }

        $pwdData = [pscustomobject]@{
          GPO               = $GPOName
          UserName          = $userName ?? "[NONE]"
          NewName           = $newName ?? "[NONE]"
          Password          = $password
          DecryptedPassword = $decryptedPwd ?? "[NONE]"
          Changed           = $changed ?? "[NONE]"
          NodeName          = $nodeName ?? "[NONE]"
          Type              = $passwordType
          File              = $file
        }

        return $pwdData
      }

      if ($containsCPassword) {
        $passwordType = "CPassword"
        $xml.SelectNodes("//*[@cpassword]") | foreach-object {
          $password = $_.cpassword

          if ($password -and ($password -ne "")) {
            $decryptedPwd = Get-DecryptedCPassword $password
            Write-Host "Decrypted password in $file"
          }

          $newName = $_.newName
          $userName = $_.userName ?? $_.accountName ?? $_.runAs

          $res += Get-CommonPasswordData $_
        }        
      }

      if ($containsAutoLogon) {
        $passwordType = "Autologon"
        $usernameNodes = $xml.SelectNodes("//*[@name='DefaultUserName'][@value]")

        $i = 0
        $xml.SelectNodes("//*[@name='DefaultPassword'][@value]") | foreach-object {
          $password = $_.value
          $newName = $_.newName
          $userName = $usernameNodes[$i].value

          $res += Get-CommonPasswordData $_
          $i++
        }
      }

      $res
    }

    catch {
      Write-Warning "Error while parsing '$file': $_"
    }
  }

  $HASGROUPPOLICY = $false
  if (Get-Command -Module GroupPolicy) {
    $HASGROUPPOLICY = $true
  }

  if ($Password) {
    Write-Host "Decrypting cpassword..."
    return Get-DecryptedCPassword $Password
  }

  try {
    # Retreive domain GPP files containing passwords
    if (!$Files.count -gt 0) {
      Write-Host "Retreiveing GPP files from SYSVOL. This could take a while"
      $includeFiles = @("Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml", "Registry.xml")
      $domainXMLFiles = Get-ChildItem -Force -Path "\\$Domain\SYSVOL\*\Policies" -Recurse -ErrorAction SilentlyContinue -Include $includeFiles

    }
    else {
      Write-Host "GPO Reports provided"
      $domainXMLFiles = $Files
    }

    Write-Host "Found $($domainXMLFiles.count) files that could contain password"
  }

  catch {
    Write-Error "Error while retreiving GPO Reports: $_"
  }
  
  foreach ($file in $domainXMLFiles) {
    try {
      $res = Get-PasswordFromXML $file
      $res
    }

    catch {
      Write-Error "Invalid XML file"
    }
  }
}