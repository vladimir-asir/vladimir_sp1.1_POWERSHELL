# 1. Crear usuarios de prueba con directorios de trabajo
$password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

# Usuario 1: Con archivos en directorio trabajo
New-ADUser -Name "Juan Perez Garcia" -SamAccountName "jpgarci" `
    -UserPrincipalName "jpgarci@empresa.local" -GivenName "Juan" `
    -Surname "Perez Garcia" -AccountPassword $password -Enabled $true `
    -Path "OU=Domain Controllers,DC=vladimirasir,DC=local"

# Crear su directorio y archivos
New-Item -Path "C:\Users\jpgarci\trabajo" -ItemType Directory -Force
1..3 | ForEach-Object { "Contenido archivo $_" | Out-File "C:\Users\jpgarci\trabajo\documento$_.txt" }

# Usuario 2: Sin archivos
New-ADUser -Name "Maria Lopez" -SamAccountName "mlopez" `
    -UserPrincipalName "mlopez@empresa.local" -GivenName "Maria" `
    -Surname "Lopez" -AccountPassword $password -Enabled $true `
    -Path "OU=Domain Controllers,DC=vladimirasir,DC=local"
New-Item -Path "C:\Users\mlopez\trabajo" -ItemType Directory -Force

# Usuario 3: Con muchos archivos
New-ADUser -Name "Carlos Rodriguez" -SamAccountName "crodrig" `
    -UserPrincipalName "crodrig@empresa.local" -GivenName "Carlos" `
    -Surname "Rodriguez" -AccountPassword $password -Enabled $true `
    -Path "OU=Domain Controllers,DC=vladimirasir,DC=local"
New-Item -Path "C:\Users\crodrig\trabajo" -ItemType Directory -Force
1..5 | ForEach-Object { "Proyecto $_ contenido" | Out-File "C:\Users\crodrig\trabajo\proyecto$_.docx" }

# 2. Crear archivo de bajas
@"
Juan:Perez:Garcia:jpgarci
Maria:Lopez:Martinez:mlopez
Carlos:Rodriguez:Sanchez:crodrig
Usuario:No:Existe:noexiste
Ana:Garcia:Fernandez:agarcia
"@ | Out-File "C:\bajas.txt" -Encoding UTF8