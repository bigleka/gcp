#pip install google-cloud-monitoring
#gcloud auth application-default login
import csv
import time
from datetime import datetime, timedelta, timezone
from google.cloud import monitoring_v3

# ==========================================
# 1. Configurações
# ==========================================
PROJECT_ID = "project_id"
DATABASE_ID = "project_id:instancia" 
ARQUIVO_SAIDA = "metricas_cloudsql_completo.csv"

DIAS_TOTAL = 120
TAMANHO_LOTE_DIAS = 5 

def extrair_por_lotes():
    client = monitoring_v3.MetricServiceClient()
    project_name = f"projects/{PROJECT_ID}"
    
    fim_total = datetime.now(timezone.utc)
    inicio_total = fim_total - timedelta(days=DIAS_TOTAL)
    
    print(f"Iniciando extração Dupla (CPU e RAM) de {DIAS_TOTAL} dias para o Cloud SQL: {DATABASE_ID}...")

    # Abrindo o CSV com as novas colunas
    with open(ARQUIVO_SAIDA, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Database ID', 'Data/Hora (UTC)', 'CPU (%)', 'Memória (%)'])

        ponto_atual = inicio_total
        while ponto_atual < fim_total:
            ponto_final_lote = min(ponto_atual + timedelta(days=TAMANHO_LOTE_DIAS), fim_total)
            
            print(f"\n-> Lote: {ponto_atual.strftime('%d/%m')} até {ponto_final_lote.strftime('%d/%m')}")
            
            interval = monitoring_v3.TimeInterval({
                "end_time": {"seconds": int(ponto_final_lote.timestamp())},
                "start_time": {"seconds": int(ponto_atual.timestamp())},
            })

            # Filtros separados para CPU e Memória
            filtro_base = f'AND resource.labels.database_id="{DATABASE_ID}"'
            filtro_cpu = f'metric.type="cloudsql.googleapis.com/database/cpu/utilization" {filtro_base}'
            filtro_mem = f'metric.type="cloudsql.googleapis.com/database/memory/utilization" {filtro_base}'

            # Dicionário para agrupar as métricas pelo timestamp
            dados_combinados = {}

            try:
                # --- EXTRAÇÃO DA CPU ---
                print("   Buscando CPU...")
                res_cpu = client.list_time_series(request={"name": project_name, "filter": filtro_cpu, "interval": interval, "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL})
                
                for serie in res_cpu:
                    for point in serie.points:
                        # Arredonda para o minuto exato para alinhar com a memória
                        dt = datetime.fromtimestamp(point.interval.start_time.timestamp(), tz=timezone.utc).replace(second=0, microsecond=0)
                        dt_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                        
                        dados_combinados[dt_str] = {
                            'cpu': round(point.value.double_value * 100, 2),
                            'mem': '' # Deixa em branco inicialmente
                        }

                # --- EXTRAÇÃO DA MEMÓRIA ---
                print("   Buscando Memória...")
                res_mem = client.list_time_series(request={"name": project_name, "filter": filtro_mem, "interval": interval, "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL})
                
                for serie in res_mem:
                    for point in serie.points:
                        dt = datetime.fromtimestamp(point.interval.start_time.timestamp(), tz=timezone.utc).replace(second=0, microsecond=0)
                        dt_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                        valor_memoria = round(point.value.double_value * 100, 2)
                        
                        # Se a chave da data já existe (criada pela CPU), atualiza a memória. 
                        # Se não existe, cria a linha só com a memória.
                        if dt_str in dados_combinados:
                            dados_combinados[dt_str]['mem'] = valor_memoria
                        else:
                            dados_combinados[dt_str] = {'cpu': '', 'mem': valor_memoria}

                # --- GRAVANDO O LOTE NO CSV ---
                # Ordenamos pelas chaves (datas) para o CSV ficar cronológico
                linhas_gravadas = 0
                for data_hora, valores in sorted(dados_combinados.items()):
                    writer.writerow([DATABASE_ID, data_hora, valores['cpu'], valores['mem']])
                    linhas_gravadas += 1
                
                print(f"   Sucesso! {linhas_gravadas} linhas consolidadas salvas.")
                
                time.sleep(1.5) # Pausa ligeiramente maior por fazermos 2 requisições
                ponto_atual = ponto_final_lote

            except Exception as e:
                print(f"   ERRO no lote: {e}")
                print("   Tentando o próximo...")
                ponto_atual = ponto_final_lote

    print(f"\nFinalizado! CSV salvo em: {ARQUIVO_SAIDA}")

if __name__ == "__main__":
    extrair_por_lotes()