
Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ArchivoBajas,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

$logDirectory = "C:\Windows\Logs"
$projectDirectory = "C:\Users\proyecto"
$logFileBajas = Join-Path $logDirectory "bajas.log"
$logFileErrors = Join-Path $logDirectory "bajaserror.log"

function Write-Log {
    param(
        [string]$Message,
        [string]$LogFile,
        [switch]$IsError
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    
    if ($DryRun) {
        $prefix = if ($IsError) { "[SIMULACION-ERROR]" } else { "[SIMULACION-LOG]" }
        Write-Host "$prefix $Message" -ForegroundColor $(if ($IsError) { "Yellow" } else { "Cyan" })
    } else {
        Add-Content -Path $LogFile -Value $logEntry
        if ($IsError) {
            Write-Host "[ERROR] $Message" -ForegroundColor Red
        }
    }
}

function Test-Parameters {
    if (-not (Test-Path $ArchivoBajas)) {
        Write-Host "ERROR: El archivo '$ArchivoBajas' no existe." -ForegroundColor Red
        exit 1
    }
    
    if ((Get-Item $ArchivoBajas) -is [System.IO.DirectoryInfo]) {
        Write-Host "ERROR: '$ArchivoBajas' es un directorio, no un archivo." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Validacion de parametros correcta" -ForegroundColor Green
}

function Remove-UserFromSystem {
    param(
        [string]$Login,
        [string]$Nombre,
        [string]$Apellido1,
        [string]$Apellido2
    )
    
    $nombreCompleto = "$Nombre $Apellido1 $Apellido2"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    Write-Host "Procesando usuario: $Login ($nombreCompleto)" -ForegroundColor Cyan
    
    try {
        $user = Get-ADUser -Identity $Login -ErrorAction Stop
        Write-Host "  Usuario '$Login' encontrado en el sistema" -ForegroundColor Green
    } catch {
        $errorMsg = "$timestamp-$Login-$nombreCompleto-Usuario no existe en el sistema"
        Write-Log -Message $errorMsg -LogFile $logFileErrors -IsError
        Write-Host "  Usuario '$Login' NO encontrado. Registrado en log de errores." -ForegroundColor Red
        return
    }
    
    try {
        $homeDirectory = (Get-ADUser -Identity $Login -Properties HomeDirectory).HomeDirectory
        
        if (-not $homeDirectory) {
            $homeDirectory = "C:\Users\$Login"
        }
        
        $workDirectory = Join-Path $homeDirectory "trabajo"
        
        Write-Host "  Directorio personal: $homeDirectory" -ForegroundColor Gray
        Write-Host "  Directorio trabajo: $workDirectory" -ForegroundColor Gray
        
    } catch {
        $errorMsg = "$timestamp-$Login-$nombreCompleto-Error al obtener directorio personal"
        Write-Log -Message $errorMsg -LogFile $logFileErrors -IsError
        return
    }
    
    $userProjectFolder = Join-Path $projectDirectory $Login
    
    if ($DryRun) {
        Write-Host "  [SIMULACION] Se crearia la carpeta: $userProjectFolder" -ForegroundColor Yellow
    } else {
        if (-not (Test-Path $userProjectFolder)) {
            try {
                New-Item -Path $userProjectFolder -ItemType Directory -Force | Out-Null
                Write-Host "  Carpeta de proyecto creada: $userProjectFolder" -ForegroundColor Green
            } catch {
                $errorMsg = "$timestamp-$Login-$nombreCompleto-Error al crear carpeta de proyecto: $_"
                Write-Log -Message $errorMsg -LogFile $logFileErrors -IsError
                return
            }
        }
    }
    
    $movedFiles = @()
    $fileCount = 0
    
    if (Test-Path $workDirectory) {
        try {
            $files = Get-ChildItem -Path $workDirectory -File
            
            if ($files.Count -eq 0) {
                Write-Host "  INFO: No hay archivos en el directorio trabajo" -ForegroundColor Yellow
            } else {
                foreach ($file in $files) {
                    $fileCount++
                    $destinationPath = Join-Path $userProjectFolder $file.Name
                    
                    if ($DryRun) {
                        Write-Host "  [SIMULACION] Se moveria: $($file.Name)" -ForegroundColor Yellow
                        $movedFiles += "$fileCount. $($file.Name)"
                    } else {
                        try {
                            Move-Item -Path $file.FullName -Destination $destinationPath -Force
                            $movedFiles += "$fileCount. $($file.Name)"
                            Write-Host "  Movido: $($file.Name)" -ForegroundColor Green
                        } catch {
                            Write-Host "  Error al mover: $($file.Name) - $_" -ForegroundColor Red
                        }
                    }
                }
            }
        } catch {
            Write-Host "  Error al acceder al directorio trabajo: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "  INFO: El directorio trabajo no existe" -ForegroundColor Yellow
    }
    
    $logEntry = @"
================================================================================
Fecha y hora: $timestamp
Login: $Login
Nombre completo: $nombreCompleto
Carpeta destino: $userProjectFolder
Archivos movidos:
$($movedFiles -join "`n")
Total de archivos: $fileCount
================================================================================
"@
    
    Write-Log -Message $logEntry -LogFile $logFileBajas
    
    if (-not $DryRun -and $fileCount -gt 0) {
        try {
            $adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
            $admin = $adminSID.Translate([System.Security.Principal.NTAccount])
            
            $filesInProject = Get-ChildItem -Path $userProjectFolder -File
            foreach ($file in $filesInProject) {
                $acl = Get-Acl $file.FullName
                $acl.SetOwner($admin)
                Set-Acl -Path $file.FullName -AclObject $acl
            }
            
            Write-Host "  Propietario cambiado a Administrador" -ForegroundColor Green
        } catch {
            Write-Host "  Error al cambiar propietario: $_" -ForegroundColor Red
        }
    }
    
    if ($DryRun) {
        Write-Host "  [SIMULACION] Se eliminaria el usuario '$Login' y su directorio personal" -ForegroundColor Yellow
    } else {
        try {
            if (Test-Path $homeDirectory) {
                Remove-Item -Path $homeDirectory -Recurse -Force
                Write-Host "  Directorio personal eliminado" -ForegroundColor Green
            }
            
            Remove-ADUser -Identity $Login -Confirm:$false
            Write-Host "  Usuario '$Login' eliminado del sistema" -ForegroundColor Green
            
        } catch {
            $errorMsg = "$timestamp-$Login-$nombreCompleto-Error al eliminar usuario: $_"
            Write-Log -Message $errorMsg -LogFile $logFileErrors -IsError
        }
    }
}

Write-Host "SISTEMA DE GESTION DE BAJAS DE USUARIOS - VILLA S.L." -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "[MODO SIMULACION ACTIVADO - No se realizaran cambios reales]" -ForegroundColor Yellow -BackgroundColor DarkYellow
}

Test-Parameters

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "Modulo ActiveDirectory cargado" -ForegroundColor Green
} catch {
    Write-Host "ERROR: No se puede cargar el modulo ActiveDirectory" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $logDirectory)) {
    if ($DryRun) {
        Write-Host "[SIMULACION] Se crearia el directorio: $logDirectory" -ForegroundColor Yellow
    } else {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
        Write-Host "Directorio de logs creado: $logDirectory" -ForegroundColor Green
    }
}

if (-not (Test-Path $projectDirectory)) {
    if ($DryRun) {
        Write-Host "[SIMULACION] Se crearia el directorio: $projectDirectory" -ForegroundColor Yellow
    } else {
        New-Item -Path $projectDirectory -ItemType Directory -Force | Out-Null
        Write-Host "Directorio de proyectos creado: $projectDirectory" -ForegroundColor Green
    }
}

Write-Host "Leyendo archivo de bajas: $ArchivoBajas" -ForegroundColor Cyan

try {
    $content = Get-Content -Path $ArchivoBajas -ErrorAction Stop
    $totalUsers = ($content | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
    Write-Host "Archivo leido correctamente. Total de usuarios a procesar: $totalUsers" -ForegroundColor Green
} catch {
    Write-Host "ERROR: No se pudo leer el archivo '$ArchivoBajas': $_" -ForegroundColor Red
    exit 1
}

$processedCount = 0
foreach ($line in $content) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }
    
    $processedCount++
    
    $parts = $line.Split(':')
    
    if ($parts.Count -ne 4) {
        Write-Host "ERROR: Formato incorrecto en linea: $line" -ForegroundColor Red
        Write-Host "  Formato esperado: nombre:apellido1:apellido2:login" -ForegroundColor Yellow
        continue
    }
    
    $nombre = $parts[0].Trim()
    $apellido1 = $parts[1].Trim()
    $apellido2 = $parts[2].Trim()
    $login = $parts[3].Trim()
    
    Remove-UserFromSystem -Login $login -Nombre $nombre -Apellido1 $apellido1 -Apellido2 $apellido2
}

Write-Host "PROCESO COMPLETADO" -ForegroundColor Green
Write-Host "Total de usuarios procesados: $processedCount" -ForegroundColor Cyan
Write-Host "Log de bajas: $logFileBajas" -ForegroundColor Gray
Write-Host "Log de errores: $logFileErrors" -ForegroundColor Gray

if ($DryRun) {
    Write-Host "RECORDATORIO: Modo simulacion - No se realizaron cambios reales" -ForegroundColor Yellow
}

Write-Host "`nScript finalizado." -ForegroundColor Green