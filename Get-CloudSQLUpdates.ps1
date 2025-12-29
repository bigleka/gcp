function Get-CloudSQLUpdates {
    <#
    .SYNOPSIS
        Lista atualizações pendentes e agendadas de instâncias Cloud SQL em todos os projetos.
    
    .DESCRIPTION
        Analisa todos os projetos acessíveis no GCP, lista as instâncias Cloud SQL e verifica
        se há janelas de manutenção agendadas ou patches de versão disponíveis.
        
    .PARAMETER CredentialFile
        Caminho para o arquivo JSON de Service Account. Se omitido, usa a sessão atual do gcloud.
        
    .EXAMPLE
        Get-CloudSQLUpdates
        Usa a autenticação atual do gcloud CLI (gcloud auth login).
        
    .EXAMPLE
        Get-CloudSQLUpdates -CredentialFile "C:\chaves\minha-sa.json" | Format-Table Projeto, Instancia, UpdateStatus, DataAgendada, PatchDisponivel
        Autentica temporariamente usando o arquivo JSON fornecido, exibindo em um formato de tabela 
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$CredentialFile
    )

    process {
        # 1. Autenticação
        if ($CredentialFile) {
            Write-Host "🔑 Autenticando com arquivo: $CredentialFile" -ForegroundColor Cyan
            # Ativa a conta de serviço (nota: isso altera a conta ativa globalmente no gcloud)
            gcloud auth activate-service-account --key-file="$CredentialFile" --quiet | Out-Null
        }

        Write-Host "🎫 Obtendo token de acesso..." -ForegroundColor Cyan
        try {
            $token = gcloud auth print-access-token --quiet
            if (-not $token) { throw "Não foi possível obter o token. Verifique o login." }
        }
        catch {
            Write-Error "Erro ao obter token do gcloud. Certifique-se que o Google Cloud SDK está instalado."
            return
        }

        $headers = @{ "Authorization" = "Bearer $token" }

        # 2. Listar Projetos
        Write-Host "🌍 Listando projetos ativos..." -ForegroundColor Cyan
        $projectsUrl = "https://cloudresourcemanager.googleapis.com/v1/projects"
        $projects = @()
        
        do {
            try {
                $resp = Invoke-RestMethod -Uri $projectsUrl -Headers $headers -Method Get
                $projects += $resp.projects | Where-Object { $_.lifecycleState -eq "ACTIVE" }
                
                if ($resp.nextPageToken) {
                    $projectsUrl = "https://cloudresourcemanager.googleapis.com/v1/projects?pageToken=$($resp.nextPageToken)"
                } else {
                    $projectsUrl = $null
                }
            } catch {
                Write-Warning "Erro ao listar projetos: $_"
                $projectsUrl = $null
            }
        } while ($projectsUrl)

        $totalProjs = $projects.Count
        Write-Host "Total de projetos encontrados: $totalProjs" -ForegroundColor Green

        # 3. Listar Instâncias e Verificar Updates
        $results = @()
        $counter = 0

        foreach ($proj in $projects) {
            $counter++
            $pidStr = $proj.projectId
            
            # Barra de progresso visual
            Write-Progress -Activity "Verificando Cloud SQL" -Status "Analisando $pidStr" -PercentComplete (($counter / $totalProjs) * 100)

            $urlInstance = "https://sqladmin.googleapis.com/v1/projects/$pidStr/instances"
            
            try {
                $instResp = Invoke-RestMethod -Uri $urlInstance -Headers $headers -Method Get -ErrorAction SilentlyContinue
                
                if ($instResp.items) {
                    foreach ($inst in $instResp.items) {
                        # Lógica de detecção de update (Portada do Python)
                        $statusUpdate = "OK"
                        $agendadoPara = $null
                        $patches = $null
                        
                        # Verifica agendamento forçado
                        if ($inst.scheduledMaintenance) {
                            $statusUpdate = "SCHEDULED"
                            $rawTime = $inst.scheduledMaintenance.startTime # ex: 2023-10-27T03:00:00.000Z
                            if ($rawTime) {
                                $agendadoPara = [DateTime]::Parse($rawTime)
                            }
                        }
                        # Verifica updates disponíveis (array)
                        elseif ($inst.availableMaintenanceVersions) {
                            $statusUpdate = "AVAILABLE"
                            # Garante que seja tratado como array e une com vírgula
                            $patches = (@($inst.availableMaintenanceVersions) -join ", ")
                        }

                        # Cria o objeto de saída
                        $obj = [PSCustomObject]@{
                            Projeto         = $pidStr
                            Instancia       = $inst.name
                            VersaoDB        = $inst.databaseVersion
                            Status          = $inst.state
                            UpdateStatus    = $statusUpdate
                            DataAgendada    = $agendadoPara
                            PatchDisponivel = $patches
                        }
                        $results += $obj
                    }
                }
            }
            catch {
                # Ignora erros de API não habilitada por projeto para não sujar a tela
                # Write-Verbose "API não habilitada ou erro em $pidStr"
            }
        }
        
        Write-Progress -Activity "Verificando Cloud SQL" -Completed

        # 4. Retorna os resultados ordenados (Agendados primeiro)
        # Ordem customizada: SCHEDULED (0), AVAILABLE (1), OK (2)
        return $results | Sort-Object @{Expression={
            switch ($_.UpdateStatus) {
                "SCHEDULED" { 0 }
                "AVAILABLE" { 1 }
                "OK"        { 2 }
            }
        }}, DataAgendada
    }
}
