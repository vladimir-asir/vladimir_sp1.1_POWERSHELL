
Param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('G','U','M','AG','LIST')]
    [string]$Accion,
    
    [Parameter(Mandatory=$false)]
    [string]$Param2,
    
    [Parameter(Mandatory=$false)]
    [string]$Param3,
    
    [Parameter(Mandatory=$false)]
    [string]$Param4,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "ERROR: El módulo ActiveDirectory no está disponible." -ForegroundColor Red
    Write-Host "Asegúrate de ejecutar este script en un controlador de dominio o con RSAT instalado." -ForegroundColor Yellow
    exit 1
}

function Test-PasswordComplexity {
    param(
        [string]$Password
    )
    
    if ($Password.Length -lt 8) {
        return @{
            Valid = $false
            Reason = "La contraseña debe tener al menos 8 caracteres"
        }
    }
    
    $hasUpper = $Password -cmatch '[A-Z]'
    $hasLower = $Password -cmatch '[a-z]'
    $hasDigit = $Password -match '\d'
    $hasSpecial = $Password -match '[^a-zA-Z0-9]'
    
    $complexityCount = 0
    if ($hasUpper) { $complexityCount++ }
    if ($hasLower) { $complexityCount++ }
    if ($hasDigit) { $complexityCount++ }
    if ($hasSpecial) { $complexityCount++ }
    
    if ($complexityCount -lt 3) {
        return @{
            Valid = $false
            Reason = "La contraseña debe contener al menos 3 de estas categorías: mayúsculas, minúsculas, números, caracteres especiales"
        }
    }
    
    return @{
        Valid = $true
        Reason = "Contraseña válida"
    }
}

function New-RandomPassword {
    param(
        [int]$Length = 12
    )
    
    $upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $lowerChars = 'abcdefghijklmnopqrstuvwxyz'
    $digitChars = '0123456789'
    $specialChars = '!@#$%^&*()-_=+[]{}|;:,.<>?'
    
    $password = ''
    $password += $upperChars[(Get-Random -Maximum $upperChars.Length)]
    $password += $lowerChars[(Get-Random -Maximum $lowerChars.Length)]
    $password += $digitChars[(Get-Random -Maximum $digitChars.Length)]
    $password += $specialChars[(Get-Random -Maximum $specialChars.Length)]
    
    $allChars = $upperChars + $lowerChars + $digitChars + $specialChars
    for ($i = $password.Length; $i -lt $Length; $i++) {
        $password += $allChars[(Get-Random -Maximum $allChars.Length)]
    }
    
    $passwordArray = $password.ToCharArray()
    $shuffled = $passwordArray | Get-Random -Count $passwordArray.Length
    
    return -join $shuffled
}

switch ($Accion) {
    
    'G' {
        if (-not $Param2) {
            Write-Host "ERROR: Debes especificar el nombre del grupo." -ForegroundColor Red
            exit 1
        }
        
        $groupName = $Param2
        $groupScope = $Param3
        $groupCategory = $Param4
        
        if ($groupScope -notin @('Global','Universal','DomainLocal')) {
            Write-Host "ERROR: El ambito debe ser Global, Universal o DomainLocal." -ForegroundColor Red
            exit 1
        }
        
        if ($groupCategory -notin @('Security','Distribution')) {
            Write-Host "ERROR: El tipo debe ser Security o Distribution." -ForegroundColor Red
            exit 1
        }
        
        if ($DryRun) {
            Write-Host "`n[MODO SIMULACION]" -ForegroundColor Cyan
            Write-Host "Se crearia el grupo con los siguientes parametros:" -ForegroundColor Yellow
            Write-Host "  Nombre: $groupName"
            Write-Host "  Ambito: $groupScope"
            Write-Host "  Categoria: $groupCategory"
            exit 0
        }
        
        try {
            $existingGroup = Get-ADGroup -Identity $groupName -ErrorAction Stop
            Write-Host "INFO: El grupo '$groupName' ya existe en el dominio." -ForegroundColor Yellow
        } catch {
            try {
                New-ADGroup -Name $groupName -GroupScope $groupScope -GroupCategory $groupCategory
                Write-Host "EXITO: Grupo '$groupName' creado correctamente." -ForegroundColor Green
                Write-Host "  Ambito: $groupScope"
                Write-Host "  Categoria: $groupCategory"
            } catch {
                Write-Host "ERROR: No se pudo crear el grupo. $_" -ForegroundColor Red
                exit 1
            }
        }
    }
    
    'U' {
        if (-not $Param2) {
            Write-Host "ERROR: Debes especificar el nombre del usuario." -ForegroundColor Red
            exit 1
        }
        
        if (-not $Param3) {
            Write-Host "ERROR: Debes especificar la Unidad Organizativa." -ForegroundColor Red
            exit 1
        }
        
        $userName = $Param2
        $ouPath = $Param3
        
        $randomPassword = New-RandomPassword
        $securePassword = ConvertTo-SecureString $randomPassword -AsPlainText -Force
        
        if ($DryRun) {
            Write-Host "`n[MODO SIMULACION]" -ForegroundColor Cyan
            Write-Host "Se crearia el usuario con los siguientes parametros:" -ForegroundColor Yellow
            Write-Host "  Usuario: $userName"
            Write-Host "  UO: $ouPath"
            Write-Host "  Contraseña: [Generada aleatoriamente]"
            Write-Host "  Cambio obligatorio en primer inicio: Si"
            exit 0
        }
        
        try {
            $ou = Get-ADOrganizationalUnit -Identity $ouPath -ErrorAction Stop
        } catch {
            Write-Host "ERROR: La Unidad Organizativa '$ouPath' no existe." -ForegroundColor Red
            exit 1
        }
        
        try {
            $existingUser = Get-ADUser -Identity $userName -ErrorAction Stop
            Write-Host "INFO: El usuario '$userName' ya existe en el dominio." -ForegroundColor Yellow
        } catch {
            try {
                New-ADUser -Name $userName -SamAccountName $userName -UserPrincipalName "$userName@$env:USERDNSDOMAIN" `
                    -Path $ouPath -AccountPassword $securePassword -Enabled $true -ChangePasswordAtLogon $true
                
                Write-Host "EXITO: Usuario '$userName' creado correctamente." -ForegroundColor Green
                Write-Host "  UO: $ouPath"
                Write-Host "  Contraseña generada: $randomPassword" -ForegroundColor Cyan
                Write-Host "  IMPORTANTE: Guarda esta contraseña, el usuario debe cambiarla en el primer inicio." -ForegroundColor Yellow
            } catch {
                Write-Host "ERROR: No se pudo crear el usuario. $_" -ForegroundColor Red
                exit 1
            }
        }
    }
    
    'M' {
        if (-not $Param2) {
            Write-Host "ERROR: Debes especificar el nombre del usuario." -ForegroundColor Red
            exit 1
        }
        
        if (-not $Param3) {
            Write-Host "ERROR: Debes especificar la nueva contraseña." -ForegroundColor Red
            exit 1
        }
        
        if (-not $Param4) {
            Write-Host "ERROR: Debes especificar Enable o Disable para el estado de la cuenta." -ForegroundColor Red
            exit 1
        }
        
        $userName = $Param2
        $newPassword = $Param3
        $accountAction = $Param4
        
        $passwordCheck = Test-PasswordComplexity -Password $newPassword
        
        if (-not $passwordCheck.Valid) {
            Write-Host "ERROR: La contraseña no cumple los requisitos de complejidad." -ForegroundColor Red
            Write-Host "  Motivo: $($passwordCheck.Reason)" -ForegroundColor Yellow
            exit 1
        }
        
        if ($accountAction -notin @('Enable','Disable')) {
            Write-Host "ERROR: El estado debe ser Enable o Disable." -ForegroundColor Red
            exit 1
        }
        
        if ($DryRun) {
            Write-Host "`n[MODO SIMULACION]" -ForegroundColor Cyan
            Write-Host "Se modificaria el usuario con los siguientes cambios:" -ForegroundColor Yellow
            Write-Host "  Usuario: $userName"
            Write-Host "  Nueva contraseña: [Cumple requisitos de complejidad]"
            Write-Host "  Estado de cuenta: $accountAction"
            exit 0
        }
        
        try {
            $user = Get-ADUser -Identity $userName -ErrorAction Stop
        } catch {
            Write-Host "ERROR: El usuario '$userName' no existe." -ForegroundColor Red
            exit 1
        }
        
        try {
            $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
            Set-ADAccountPassword -Identity $userName -NewPassword $securePassword -Reset
            Write-Host "EXITO: Contraseña del usuario '$userName' modificada correctamente." -ForegroundColor Green
        } catch {
            Write-Host "ERROR: No se pudo cambiar la contraseña. $_" -ForegroundColor Red
            exit 1
        }
        
        try {
            if ($accountAction -eq 'Enable') {
                Enable-ADAccount -Identity $userName
                Write-Host "EXITO: Cuenta de usuario '$userName' habilitada." -ForegroundColor Green
            } else {
                Disable-ADAccount -Identity $userName
                Write-Host "EXITO: Cuenta de usuario '$userName' deshabilitada." -ForegroundColor Green
            }
        } catch {
            Write-Host "ERROR: No se pudo cambiar el estado de la cuenta. $_" -ForegroundColor Red
            exit 1
        }
    }
    
    'AG' {
        if (-not $Param2) {
            Write-Host "ERROR: Debes especificar el nombre del usuario." -ForegroundColor Red
            exit 1
        }
        
        if (-not $Param3) {
            Write-Host "ERROR: Debes especificar el nombre del grupo." -ForegroundColor Red
            exit 1
        }
        
        $userName = $Param2
        $groupName = $Param3
        
        if ($DryRun) {
            Write-Host "`n[MODO SIMULACION]" -ForegroundColor Cyan
            Write-Host "Se añadiria el usuario al grupo:" -ForegroundColor Yellow
            Write-Host "  Usuario: $userName"
            Write-Host "  Grupo: $groupName"
            exit 0
        }
        
        try {
            $user = Get-ADUser -Identity $userName -ErrorAction Stop
        } catch {
            Write-Host "ERROR: El usuario '$userName' no existe." -ForegroundColor Red
            exit 1
        }
        
        try {
            $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
        } catch {
            Write-Host "ERROR: El grupo '$groupName' no existe." -ForegroundColor Red
            exit 1
        }
        
        try {
            Add-ADGroupMember -Identity $groupName -Members $userName
            Write-Host "EXITO: Usuario '$userName' añadido al grupo '$groupName'." -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -match "ya es miembro") {
                Write-Host "INFO: El usuario '$userName' ya es miembro del grupo '$groupName'." -ForegroundColor Yellow
            } else {
                Write-Host "ERROR: No se pudo añadir el usuario al grupo. $_" -ForegroundColor Red
                exit 1
            }
        }
    }
    
    'LIST' {
        if (-not $Param2) {
            Write-Host "ERROR: Debes especificar que listar: Usuarios, Grupos o Ambos." -ForegroundColor Red
            exit 1
        }
        
        $listType = $Param2
        $ouFilter = $Param3
        
        if ($listType -notin @('Usuarios','Grupos','Ambos')) {
            Write-Host "ERROR: El tipo debe ser Usuarios, Grupos o Ambos." -ForegroundColor Red
            exit 1
        }
        
        if ($DryRun) {
            Write-Host "`n[MODO SIMULACION]" -ForegroundColor Cyan
            Write-Host "Se listarian los objetos con estos parametros:" -ForegroundColor Yellow
            Write-Host "  Tipo: $listType"
            if ($ouFilter) {
                Write-Host "  Filtro UO: $ouFilter"
            }
            exit 0
        }
        
        if ($listType -in @('Usuarios','Ambos')) {
            Write-Host "`n=== USUARIOS ===" -ForegroundColor Cyan
            
            if ($ouFilter) {
                try {
                    Get-ADUser -Filter * -SearchBase $ouFilter -Properties Enabled,DistinguishedName | 
                        Select-Object Name, SamAccountName, Enabled, DistinguishedName | 
                        Format-Table -AutoSize
                } catch {
                    Write-Host "ERROR: No se pudo listar usuarios en '$ouFilter'. $_" -ForegroundColor Red
                }
            } else {
                Get-ADUser -Filter * -Properties Enabled | 
                    Select-Object Name, SamAccountName, Enabled | 
                    Sort-Object Name | 
                    Format-Table -AutoSize
            }
        }
        
        if ($listType -in @('Grupos','Ambos')) {
            Write-Host "`n=== GRUPOS ===" -ForegroundColor Cyan
            
            if ($ouFilter) {
                try {
                    Get-ADGroup -Filter * -SearchBase $ouFilter -Properties GroupScope,GroupCategory | 
                        Select-Object Name, GroupScope, GroupCategory, DistinguishedName | 
                        Format-Table -AutoSize
                } catch {
                    Write-Host "ERROR: No se pudo listar grupos en '$ouFilter'. $_" -ForegroundColor Red
                }
            } else {
                Get-ADGroup -Filter * -Properties GroupScope,GroupCategory | 
                    Select-Object Name, GroupScope, GroupCategory | 
                    Sort-Object Name | 
                    Format-Table -AutoSize
            }
        }
    }
    
    default {
        Write-Host "`n╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║          SCRIPT DE ADMINISTRACION DE ACTIVE DIRECTORY            ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        
        Write-Host "`nDebe especificar una accion mediante el parametro -Accion`n" -ForegroundColor Yellow
        Write-Host "ACCIONES DISPONIBLES:" -ForegroundColor Cyan
        Write-Host "`n  -Accion G (Crear Grupo)" -ForegroundColor Green
        Write-Host "    Parametros adicionales:"
        Write-Host "      -Param2: Nombre del grupo"
        Write-Host "      -Param3: Ambito (Global, Universal, DomainLocal)"
        Write-Host "      -Param4: Categoria (Security, Distribution)"
        Write-Host "    Ejemplo: .\nombre02.ps1 -Accion G -Param2 'Desarrolladores' -Param3 Global -Param4 Security"
        
        Write-Host "`n  -Accion U (Crear Usuario)" -ForegroundColor Green
        Write-Host "    Parametros adicionales:"
        Write-Host "      -Param2: Nombre del usuario (login)"
        Write-Host "      -Param3: Unidad Organizativa (Distinguished Name)"
        Write-Host "    Ejemplo: .\nombre02.ps1 -Accion U -Param2 'jperez' -Param3 'OU=Usuarios,DC=empresa,DC=local'"
        
        Write-Host "`n  -Accion M (Modificar Usuario)" -ForegroundColor Green
        Write-Host "    Parametros adicionales:"
        Write-Host "      -Param2: Nombre del usuario (login)"
        Write-Host "      -Param3: Nueva contraseña"
        Write-Host "      -Param4: Estado de cuenta (Enable o Disable)"
        Write-Host "    Ejemplo: .\nombre02.ps1 -Accion M -Param2 'jperez' -Param3 'P@ssw0rd123!' -Param4 Enable"
        
        Write-Host "`n  -Accion AG (Asignar usuario a Grupo)" -ForegroundColor Green
        Write-Host "    Parametros adicionales:"
        Write-Host "      -Param2: Nombre del usuario (login)"
        Write-Host "      -Param3: Nombre del grupo"
        Write-Host "    Ejemplo: .\nombre02.ps1 -Accion AG -Param2 'jperez' -Param3 'Desarrolladores'"
        
        Write-Host "`n  -Accion LIST (Listar Objetos)" -ForegroundColor Green
        Write-Host "    Parametros adicionales:"
        Write-Host "      -Param2: Tipo (Usuarios, Grupos, Ambos)"
        Write-Host "      -Param3: [Opcional] Filtro por UO (Distinguished Name)"
        Write-Host "    Ejemplo: .\nombre02.ps1 -Accion LIST -Param2 Usuarios"
        Write-Host "    Ejemplo: .\nombre02.ps1 -Accion LIST -Param2 Ambos -Param3 'OU=Informatica,DC=empresa,DC=local'"
        
        Write-Host "`n  --DryRun (Modo Simulacion)" -ForegroundColor Cyan
        Write-Host "    Muestra que acciones realizaria sin ejecutarlas"
        Write-Host "    Ejemplo: .\nombre02.ps1 -Accion U -Param2 'test' -Param3 'OU=Test,DC=empresa,DC=local' -DryRun"
        
        Write-Host "`n═══════════════════════════════════════════════════════════════════`n"
    }
}

Write-Host "`nScript finalizado." -ForegroundColor Green