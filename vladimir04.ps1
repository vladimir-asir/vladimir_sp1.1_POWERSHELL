
Param(
    [Parameter(Mandatory=$false)]
    [string]$ScriptPath = ".\vladimir03.ps1"
)

$testLogDirectory = "C:\Windows\Logs"
$testProjectDirectory = "C:\Users\proyecto"
$testResults = @()
$totalScore = 0
$maxScore = 10

class TestResult {
    [int]$TestNumber
    [string]$TestName
    [string]$Description
    [bool]$Passed
    [string]$Expected
    [string]$Actual
    [string]$ErrorMessage
    [int]$Points
}

function Show-Header {
    param([string]$Title)
    
    Write-Host "`n==========================================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "==========================================================`n" -ForegroundColor Cyan
}

function New-TestUser {
    param(
        [string]$Login,
        [string]$Nombre,
        [string]$Apellido1,
        [string]$Apellido2,
        [switch]$CreateWorkFiles
    )
    
    try {
        $homeDir = "C:\Users\$Login"
        if (-not (Test-Path $homeDir)) {
            New-Item -Path $homeDir -ItemType Directory -Force | Out-Null
        }
        
        $workDir = Join-Path $homeDir "trabajo"
        if (-not (Test-Path $workDir)) {
            New-Item -Path $workDir -ItemType Directory -Force | Out-Null
        }
        
        if ($CreateWorkFiles) {
            1..5 | ForEach-Object {
                $fileName = "documento$_.txt"
                $filePath = Join-Path $workDir $fileName
                "Contenido de prueba del archivo $_" | Out-File -FilePath $filePath
            }
        }
        
        try {
            $existingUser = Get-ADUser -Identity $Login -ErrorAction SilentlyContinue
            if ($existingUser) {
                Write-Host "  Usuario ya existe: $Login" -ForegroundColor Yellow
                return $true
            }
        } catch {
        }
        
        $password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
        $displayName = "$Nombre $Apellido1 $Apellido2"
        
        New-ADUser -Name $displayName `
            -SamAccountName $Login `
            -UserPrincipalName "$Login@empresa.local" `
            -GivenName $Nombre `
            -Surname "$Apellido1 $Apellido2" `
            -DisplayName $displayName `
            -AccountPassword $password `
            -Enabled $true `
            -HomeDirectory $homeDir `
            -ErrorAction Stop
        
        Write-Host "  Usuario creado: $Login" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Host "  Error al crear usuario $Login : $_" -ForegroundColor Red
        return $false
    }
}

function Clear-TestEnvironment {
    Write-Host "Limpiando entorno de pruebas anterior..." -ForegroundColor Yellow
    
    $testUsers = @('test01', 'test02', 'test03', 'test04', 'test05', 
                   'noexiste01', 'noexiste02', 'test07', 'test08', 'test09a', 'test09b', 'test10')
    
    foreach ($user in $testUsers) {
        try {
            $adUser = Get-ADUser -Identity $user -ErrorAction SilentlyContinue
            if ($adUser) {
                Remove-ADUser -Identity $user -Confirm:$false -ErrorAction SilentlyContinue
            }
        } catch {
        }
        
        $homeDir = "C:\Users\$user"
        if (Test-Path $homeDir) {
            Remove-Item -Path $homeDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        $projectDir = Join-Path $testProjectDirectory $user
        if (Test-Path $projectDir) {
            Remove-Item -Path $projectDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    $logBajas = Join-Path $testLogDirectory "bajas.log"
    $logErrors = Join-Path $testLogDirectory "bajaserror.log"
    
    if (Test-Path $logBajas) {
        Remove-Item $logBajas -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $logErrors) {
        Remove-Item $logErrors -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "Entorno limpio" -ForegroundColor Green
}

function Initialize-TestEnvironment {
    Show-Header "PREPARANDO ENTORNO DE PRUEBAS"
    
    Clear-TestEnvironment
    
    if (-not (Test-Path $testProjectDirectory)) {
        New-Item -Path $testProjectDirectory -ItemType Directory -Force | Out-Null
        Write-Host "Directorio de proyectos creado" -ForegroundColor Green
    }
    
    Write-Host "Creando usuarios de prueba..." -ForegroundColor Cyan
    
    $usersCreated = 0
    $usersCreated += if (New-TestUser -Login "test01" -Nombre "Juan" -Apellido1 "Perez" -Apellido2 "Garcia" -CreateWorkFiles) {1} else {0}
    $usersCreated += if (New-TestUser -Login "test02" -Nombre "Maria" -Apellido1 "Lopez" -Apellido2 "Martinez" -CreateWorkFiles) {1} else {0}
    $usersCreated += if (New-TestUser -Login "test03" -Nombre "Carlos" -Apellido1 "Sanchez" -Apellido2 "Rodriguez" -CreateWorkFiles) {1} else {0}
    $usersCreated += if (New-TestUser -Login "test04" -Nombre "Ana" -Apellido1 "Fernandez" -Apellido2 "Gonzalez") {1} else {0}
    $usersCreated += if (New-TestUser -Login "test05" -Nombre "Pedro" -Apellido1 "Ramirez" -Apellido2 "Diaz" -CreateWorkFiles) {1} else {0}
    
    if ($usersCreated -eq 5) {
        Write-Host "Entorno de pruebas preparado correctamente" -ForegroundColor Green
    } else {
        Write-Host "Algunos usuarios no se pudieron crear, pero continuamos con las pruebas" -ForegroundColor Yellow
    }
    
    Start-Sleep -Seconds 2
}

function Invoke-Test {
    param(
        [int]$TestNumber,
        [string]$TestName,
        [string]$Description,
        [scriptblock]$TestScript,
        [string]$Expected
    )
    
    Write-Host "PRUEBA $TestNumber : $TestName" -ForegroundColor Cyan
    Write-Host "Descripcion: $Description" -ForegroundColor Gray
    
    $result = [TestResult]::new()
    $result.TestNumber = $TestNumber
    $result.TestName = $TestName
    $result.Description = $Description
    $result.Expected = $Expected
    $result.Points = 0
    
    try {
        $testOutput = & $TestScript
        $result.Passed = $testOutput.Success
        $result.Actual = $testOutput.Actual
        $result.ErrorMessage = $testOutput.ErrorMessage
        
        if ($result.Passed) {
            $result.Points = 1
            Write-Host "PRUEBA SUPERADA (+1 punto)" -ForegroundColor Green
        } else {
            Write-Host "PRUEBA FALLIDA (0 puntos)" -ForegroundColor Red
            Write-Host "  Esperado: $Expected" -ForegroundColor Yellow
            Write-Host "  Obtenido: $($result.Actual)" -ForegroundColor Yellow
            if ($result.ErrorMessage) {
                Write-Host "  Error: $($result.ErrorMessage)" -ForegroundColor Red
            }
        }
    } catch {
        $result.Passed = $false
        $result.Actual = "Excepcion durante la prueba"
        $result.ErrorMessage = $_.Exception.Message
        Write-Host "PRUEBA FALLIDA - Excepcion (0 puntos)" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $result
}

$test1 = {
    $output = & $ScriptPath 2>&1
    $success = $output -match "ERROR.*parametro" -or $output -match "Missing.*mandatory"
    
    return @{
        Success = $success
        Actual = if ($success) { "Validacion correcta" } else { "No valida parametros" }
        ErrorMessage = ""
    }
}

$test2 = {
    $testFile = "C:\temp_bajas_test.txt"
    "Juan:Perez:Garcia:test01" | Out-File -FilePath $testFile -Encoding UTF8
    
    $output = & $ScriptPath -ArchivoBajas $testFile 2>&1
    $success = -not ($output -match "ERROR.*archivo.*existe")
    
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    
    return @{
        Success = $success
        Actual = if ($success) { "Archivo procesado" } else { "Error al procesar archivo" }
        ErrorMessage = ""
    }
}

$test3 = {
    New-TestUser -Login "test01" -Nombre "Juan" -Apellido1 "Perez" -Apellido2 "Garcia" -CreateWorkFiles | Out-Null
    
    $testFile = "C:\temp_bajas_test3.txt"
    "Juan:Perez:Garcia:test01" | Out-File -FilePath $testFile -Encoding UTF8
    
    & $ScriptPath -ArchivoBajas $testFile 2>&1 | Out-Null
    
    $userExists = $false
    try {
        $user = Get-ADUser -Identity "test01" -ErrorAction SilentlyContinue
        $userExists = $true
    } catch {
        $userExists = $false
    }
    
    $success = -not $userExists
    
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    
    return @{
        Success = $success
        Actual = if ($success) { "Usuario eliminado" } else { "Usuario aun existe" }
        ErrorMessage = ""
    }
}

$test4 = {
    New-TestUser -Login "test02" -Nombre "Maria" -Apellido1 "Lopez" -Apellido2 "Martinez" -CreateWorkFiles | Out-Null
    
    $testFile = "C:\temp_bajas_test4.txt"
    "Maria:Lopez:Martinez:test02" | Out-File -FilePath $testFile -Encoding UTF8
    
    $projectFolder = Join-Path $testProjectDirectory "test02"
    
    & $ScriptPath -ArchivoBajas $testFile 2>&1 | Out-Null
    
    $filesMoved = $false
    if (Test-Path $projectFolder) {
        $files = Get-ChildItem -Path $projectFolder -File
        $filesMoved = $files.Count -gt 0
    }
    
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    
    return @{
        Success = $filesMoved
        Actual = if ($filesMoved) { "Archivos movidos ($($files.Count) archivos)" } else { "Archivos no movidos" }
        ErrorMessage = ""
    }
}

$test5 = {
    New-TestUser -Login "test03" -Nombre "Carlos" -Apellido1 "Sanchez" -Apellido2 "Rodriguez" -CreateWorkFiles | Out-Null
    
    $testFile = "C:\temp_bajas_test5.txt"
    "Carlos:Sanchez:Rodriguez:test03" | Out-File -FilePath $testFile -Encoding UTF8
    
    $logFile = Join-Path $testLogDirectory "bajas.log"
    
    if (Test-Path $logFile) {
        Remove-Item $logFile -Force -ErrorAction SilentlyContinue
    }
    
    & $ScriptPath -ArchivoBajas $testFile 2>&1 | Out-Null
    
    $logExists = Test-Path $logFile
    $logHasContent = $false
    
    if ($logExists) {
        $content = Get-Content $logFile -Raw
        $logHasContent = $content -match "test03"
    }
    
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    
    return @{
        Success = ($logExists -and $logHasContent)
        Actual = if ($logExists -and $logHasContent) { "Log generado correctamente" } else { "Log no generado o vacio" }
        ErrorMessage = ""
    }
}

$test6 = {
    $testFile = "C:\temp_bajas_test6.txt"
    "NoExiste:Usuario:Falso:noexiste01" | Out-File -FilePath $testFile -Encoding UTF8
    
    $errorLogFile = Join-Path $testLogDirectory "bajaserror.log"
    
    if (Test-Path $errorLogFile) {
        Remove-Item $errorLogFile -Force -ErrorAction SilentlyContinue
    }
    
    & $ScriptPath -ArchivoBajas $testFile 2>&1 | Out-Null
    
    $errorLogExists = Test-Path $errorLogFile
    $errorLogged = $false
    
    if ($errorLogExists) {
        $content = Get-Content $errorLogFile -Raw
        $errorLogged = $content -match "noexiste01"
    }
    
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    
    return @{
        Success = ($errorLogExists -and $errorLogged)
        Actual = if ($errorLogged) { "Error registrado correctamente" } else { "Error no registrado" }
        ErrorMessage = ""
    }
}

$test7 = {
    New-TestUser -Login "test07" -Nombre "Usuario" -Apellido1 "Test" -Apellido2 "Siete" -CreateWorkFiles | Out-Null
    
    $testFile = "C:\temp_bajas_test7.txt"
    "Usuario:Test:Siete:test07" | Out-File -FilePath $testFile -Encoding UTF8
    
    $projectFolder = Join-Path $testProjectDirectory "test07"
    
    & $ScriptPath -ArchivoBajas $testFile 2>&1 | Out-Null
    
    $ownerChanged = $false
    
    if (Test-Path $projectFolder) {
        $files = Get-ChildItem -Path $projectFolder -File
        if ($files.Count -gt 0) {
            try {
                $file = $files[0].FullName
                $acl = Get-Acl $file
                $owner = $acl.Owner
                $ownerChanged = $owner -match "Administradores" -or $owner -match "Administrator" -or $owner -match "BUILTIN\\Administrators"
            } catch {
                $ownerChanged = $false
            }
        }
    }
    
    try {
        Remove-ADUser -Identity "test07" -Confirm:$false -ErrorAction SilentlyContinue
    } catch {}
    
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    
    return @{
        Success = $ownerChanged
        Actual = if ($ownerChanged) { "Propietario cambiado a Administrador" } else { "Propietario no cambiado" }
        ErrorMessage = ""
    }
}

$test8 = {
    New-TestUser -Login "test08" -Nombre "Usuario" -Apellido1 "Test" -Apellido2 "Ocho" -CreateWorkFiles | Out-Null
    
    $testFile = "C:\temp_bajas_test8.txt"
    "Usuario:Test:Ocho:test08" | Out-File -FilePath $testFile -Encoding UTF8
    
    $homeDir = "C:\Users\test08"
    
    & $ScriptPath -ArchivoBajas $testFile 2>&1 | Out-Null
    
    $dirExists = Test-Path $homeDir
    
    try {
        Remove-ADUser -Identity "test08" -Confirm:$false -ErrorAction SilentlyContinue
    } catch {}
    
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    
    return @{
        Success = -not $dirExists
        Actual = if (-not $dirExists) { "Directorio eliminado" } else { "Directorio aun existe" }
        ErrorMessage = ""
    }
}

$test9 = {
    New-TestUser -Login "test09a" -Nombre "Juan" -Apellido1 "Multiple" -Apellido2 "Uno" -CreateWorkFiles | Out-Null
    New-TestUser -Login "test09b" -Nombre "Maria" -Apellido1 "Multiple" -Apellido2 "Dos" -CreateWorkFiles | Out-Null
    
    $testFile = "C:\temp_bajas_test9.txt"
    @"
Juan:Multiple:Uno:test09a
Maria:Multiple:Dos:test09b
"@ | Out-File -FilePath $testFile -Encoding UTF8
    
    & $ScriptPath -ArchivoBajas $testFile 2>&1 | Out-Null
    
    $user1Exists = $true
    $user2Exists = $true
    
    try { Get-ADUser -Identity "test09a" -ErrorAction SilentlyContinue } catch { $user1Exists = $false }
    try { Get-ADUser -Identity "test09b" -ErrorAction SilentlyContinue } catch { $user2Exists = $false }
    
    $success = (-not $user1Exists) -and (-not $user2Exists)
    
    try { Remove-ADUser -Identity "test09a" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    try { Remove-ADUser -Identity "test09b" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    
    return @{
        Success = $success
        Actual = if ($success) { "Multiples usuarios procesados (2/2)" } else { "Error en procesamiento multiple" }
        ErrorMessage = ""
    }
}

$test10 = {
    New-TestUser -Login "test10" -Nombre "Usuario" -Apellido1 "Test" -Apellido2 "Diez" -CreateWorkFiles | Out-Null
    
    $testFile = "C:\temp_bajas_test10.txt"
    "Usuario:Test:Diez:test10" | Out-File -FilePath $testFile -Encoding UTF8
    
    $logFile = Join-Path $testLogDirectory "bajas.log"
    
    if (Test-Path $logFile) {
        Remove-Item $logFile -Force -ErrorAction SilentlyContinue
    }
    
    & $ScriptPath -ArchivoBajas $testFile 2>&1 | Out-Null
    
    $formatCorrect = $false
    if (Test-Path $logFile) {
        $content = Get-Content $logFile -Raw
        $formatCorrect = ($content -match "Fecha y hora:") -and 
                        ($content -match "Login:") -and
                        ($content -match "Total de archivos:")
    }
    
    try {
        Remove-ADUser -Identity "test10" -Confirm:$false -ErrorAction SilentlyContinue
    } catch {}
    
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    
    return @{
        Success = $formatCorrect
        Actual = if ($formatCorrect) { "Formato correcto" } else { "Formato incorrecto" }
        ErrorMessage = ""
    }
}

Clear-Host
Show-Header "SISTEMA DE CALIFICACION AUTOMATICA - SCRIPT nombre03.ps1"

if (-not (Test-Path $ScriptPath)) {
    Write-Host "ERROR: No se encuentra el script a evaluar en: $ScriptPath" -ForegroundColor Red
    exit 1
}

Write-Host "Script a evaluar: $ScriptPath" -ForegroundColor Cyan
Write-Host "Sistema de puntuacion: 10 pruebas x 1 punto = 10 puntos maximo" -ForegroundColor Gray

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "Modulo ActiveDirectory cargado" -ForegroundColor Green
} catch {
    Write-Host "ERROR: No se puede cargar el modulo ActiveDirectory" -ForegroundColor Red
    Write-Host "Este script requiere permisos de administrador y RSAT instalado." -ForegroundColor Yellow
    exit 1
}

Initialize-TestEnvironment

Show-Header "EJECUTANDO BATTERIA DE PRUEBAS"

$testResults += Invoke-Test -TestNumber 1 -TestName "Validacion de parametros" `
    -Description "Verifica que el script valida correctamente los parametros de entrada" `
    -TestScript $test1 -Expected "Mensaje de error cuando falta parametro"

$testResults += Invoke-Test -TestNumber 2 -TestName "Procesamiento de archivo" `
    -Description "Verifica que el script procesa correctamente un archivo valido" `
    -TestScript $test2 -Expected "Archivo procesado sin errores"

$testResults += Invoke-Test -TestNumber 3 -TestName "Eliminacion de usuario" `
    -Description "Verifica que un usuario existente se elimina del sistema" `
    -TestScript $test3 -Expected "Usuario eliminado de AD"

$testResults += Invoke-Test -TestNumber 4 -TestName "Movimiento de archivos" `
    -Description "Verifica que los archivos se mueven a la carpeta de proyecto" `
    -TestScript $test4 -Expected "Archivos movidos correctamente"

$testResults += Invoke-Test -TestNumber 5 -TestName "Generacion de log de bajas" `
    -Description "Verifica que se genera el archivo bajas.log con informacion correcta" `
    -TestScript $test5 -Expected "Log generado y con contenido"

$testResults += Invoke-Test -TestNumber 6 -TestName "Registro de errores" `
    -Description "Verifica que usuarios inexistentes se registran en bajaserror.log" `
    -TestScript $test6 -Expected "Error registrado en log"

$testResults += Invoke-Test -TestNumber 7 -TestName "Cambio de propietario" `
    -Description "Verifica que los archivos cambian propietario a Administrador" `
    -TestScript $test7 -Expected "Propietario cambiado a Administrador"

$testResults += Invoke-Test -TestNumber 8 -TestName "Eliminacion de directorios" `
    -Description "Verifica que el directorio personal del usuario se elimina" `
    -TestScript $test8 -Expected "Directorio eliminado"

$testResults += Invoke-Test -TestNumber 9 -TestName "Procesamiento multiple" `
    -Description "Verifica que el script procesa multiples usuarios en un archivo" `
    -TestScript $test9 -Expected "Todos los usuarios procesados"

$testResults += Invoke-Test -TestNumber 10 -TestName "Formato de log" `
    -Description "Verifica que el formato del log cumple con las especificaciones" `
    -TestScript $test10 -Expected "Log con formato correcto"

$totalScore = ($testResults | Where-Object { $_.Passed } | Measure-Object -Property Points -Sum).Sum

Show-Header "INFORME FINAL DE CALIFICACION"

Write-Host "RESUMEN DE PRUEBAS:" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Gray

foreach ($result in $testResults) {
    $status = if ($result.Passed) { "PASS" } else { "FAIL" }
    $color = if ($result.Passed) { "Green" } else { "Red" }
    
    Write-Host "Prueba $($result.TestNumber): $($result.TestName)" -ForegroundColor Cyan
    Write-Host "  Estado: $status" -ForegroundColor $color
    Write-Host "  Puntos: $($result.Points)/1" -ForegroundColor $(if ($result.Passed) { "Green" } else { "Red" })
    Write-Host "  Esperado: $($result.Expected)" -ForegroundColor Gray
    Write-Host "  Obtenido: $($result.Actual)" -ForegroundColor Gray
    
    if (-not $result.Passed -and $result.ErrorMessage) {
        Write-Host "  Error: $($result.ErrorMessage)" -ForegroundColor Yellow
    }
}

Write-Host "`n==========================================================" -ForegroundColor Gray
Write-Host "PUNTUACION FINAL: $totalScore / $maxScore puntos" -ForegroundColor $(if ($totalScore -ge 7) { "Green" } elseif ($totalScore -ge 5) { "Yellow" } else { "Red" })

$evaluation = switch ($totalScore) {
    {$_ -ge 9} { "EXCELENTE - Script funciona perfectamente" }
    {$_ -ge 7} { "MUY BIEN - Script funciona correctamente con fallos menores" }
    {$_ -ge 5} { "BIEN - Script funciona pero requiere mejoras" }
    {$_ -ge 3} { "INSUFICIENTE - Script tiene errores significativos" }
    default { "DEFICIENTE - Script no funciona correctamente" }
}

Write-Host "Evaluacion: $evaluation" -ForegroundColor Cyan

$reportFile = "informe_calificacion_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$reportContent = @"
================================================================================
         INFORME DE CALIFICACION AUTOMATICA - vladimir03.ps1
================================================================================

Fecha y hora: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Script evaluado: $ScriptPath
Puntuacion: $totalScore / $maxScore
Evaluacion: $evaluation

================================================================================
DETALLE DE PRUEBAS
================================================================================

$($testResults | ForEach-Object {
    @"
Prueba $($_.TestNumber): $($_.TestName)
  Descripcion: $($_.Description)
  Estado: $(if ($_.Passed) { "PASS" } else { "FAIL" })
  Puntos: $($_.Points)/1
  Esperado: $($_.Expected)
  Obtenido: $($_.Actual)
  $(if ($_.ErrorMessage) { "Error: $($_.ErrorMessage)" } else { "" })

"@
} | Out-String)

================================================================================
FIN DEL INFORME
================================================================================
"@

$reportContent | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "Informe guardado en: $reportFile" -ForegroundColor Green


Write-Host "`nCalificacion completada." -ForegroundColor Green