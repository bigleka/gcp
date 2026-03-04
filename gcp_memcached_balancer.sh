#!/bin/bash
# -------------------------------------------------------------------
# Startup Script - GCP Instance Group
# Gera proxy.lua do Memcached Proxy com IPs das instâncias do grupo.
# v2
# https://leka.com.br/postgres-pg_pool2-sharding-cache/
# -------------------------------------------------------------------

set -euo pipefail

PROXY_CONF="/etc/memcached-proxy/proxy.lua"
SERVICE_NAME="memcached-proxy"
TMP_CONF="/tmp/proxy.lua.tmp"

# === Funções auxiliares ===

get_metadata() {
  curl -s -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/$1"
}

log() {
  echo "[STARTUP][$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# === Coleta de contexto GCP ===
log "Descobrindo contexto da instância..."

PROJECT_ID=$(get_metadata "project/project-id")
ZONE_FULL=$(get_metadata "instance/zone")
ZONE=${ZONE_FULL##*/}
INSTANCE_NAME=$(get_metadata "instance/name")

log "Projeto: $PROJECT_ID"
log "Zona: $ZONE"
log "Instância atual: $INSTANCE_NAME"

# === Determina o grupo de instâncias ===
INSTANCE_GROUP=$(get_metadata "instance/attributes/instance-group" || true)

if [[ -z "$INSTANCE_GROUP" ]]; then
  log "Metadado 'instance-group' não definido; tentando descobrir automaticamente..."
  INSTANCE_GROUP=$(gcloud compute instances describe "$INSTANCE_NAME" \
    --zone "$ZONE" \
    --format="value(metadata.items.instance-group)" 2>/dev/null || true)
fi

if [[ -z "$INSTANCE_GROUP" ]]; then
  log "ERRO: não foi possível determinar o Instance Group. Configure o metadado 'instance-group'."
  exit 1
fi

log "Grupo de instâncias detectado: $INSTANCE_GROUP"

# --- OTIMIZAÇÃO ---
log "Descobrindo escopo do grupo..."
REGION=${ZONE%-*} # Deriva a região da zona (ex: us-central1-a -> us-central1)

if gcloud compute instance-groups describe "$INSTANCE_GROUP" --project "$PROJECT_ID" --zone "$ZONE" &>/dev/null; then
  IG_TYPE="zonal"
  log "Tipo detectado: zonal (zona $ZONE)"
elif gcloud compute instance-groups describe "$INSTANCE_GROUP" --project "$PROJECT_ID" --region "$REGION" &>/dev/null; then
  IG_TYPE="regional"
  log "Tipo detectado: regional (região $REGION)"
else
  log "ERRO: Não foi possível encontrar o grupo '$INSTANCE_GROUP' na zona '$ZONE' ou região '$REGION'."
  exit 1
fi
# --- FIM DA OTIMIZAÇÃO ---


# === Obter IPs internos das instâncias do grupo ===
log "Coletando IPs internos das instâncias do grupo..."

local_instance_names=""

if [[ "$IG_TYPE" == "zonal" ]]; then
  local_instance_names=$(gcloud compute instance-groups list-instances "$INSTANCE_GROUP" \
    --zone "$ZONE" \
    --project "$PROJECT_ID" \
    --format="value(instance)")
else # regional
  # .basename() é uma projeção que extrai o nome da URI da instância
  local_instance_names=$(gcloud compute instance-groups list-instances "$INSTANCE_GROUP" \
    --region "$REGION" \
    --project "$PROJECT_ID" \
    --format="value(instance.basename())")
fi

# --- CORREÇÃO ROBUSTA (V6) ---
# Transforma a lista de nomes (separados por newline) em um filtro

# Filtra linhas em branco que podem ter vindo do gcloud
CLEAN_NAMES=$(echo "$local_instance_names" | grep -v '^[[:space:]]*$')

if [[ -z "$CLEAN_NAMES" ]]; then
  log "ERRO: Nenhum nome de instância válido encontrado no grupo."
  exit 1
fi

# Converte para uma lista CSV para o filtro (ex: "inst-1,inst-2,inst-3")
FILTER_LIST=$(echo "$CLEAN_NAMES" | tr '\n' ',')
FILTER_LIST=${FILTER_LIST%,} # Remove a vírgula final, se houver

log "Nomes de instância encontrados: $FILTER_LIST"

# Busca IPs de todas as instâncias de uma só vez (muito mais rápido e seguro)
INSTANCE_IPS=$(gcloud compute instances list \
  --project "$PROJECT_ID" \
  --filter="name:($FILTER_LIST)" \
  --format="value(networkInterfaces[0].networkIP)")

BACKENDS=()
while read -r ip; do
  # Adiciona apenas IPs válidos (não nulos ou com apenas espaços)
  if [[ -n "$ip" && ! "$ip" =~ ^[[:space:]]*$ ]]; then
    BACKENDS+=("$ip:11212")
  fi
done <<< "$INSTANCE_IPS"
# --- FIM DA CORREÇÃO ---


if [[ ${#BACKENDS[@]} -eq 0 ]]; then
  log "ERRO: Nenhum IP encontrado para as instâncias no filtro."
  exit 1
fi

log "Instâncias detectadas:"
printf '  - %s\n' "${BACKENDS[@]}"

# === Geração do arquivo temporário ===
mkdir -p "$(dirname "$PROXY_CONF")"

{
  echo "pools{"
  echo "    main = {"
  echo "        backends = {"
  for ip in "${BACKENDS[@]}"; do
    echo "            \"$ip\","
  done
  echo "        }"
  echo "    }"
  echo "}"
  echo ""
  echo "routes{"
  echo "    default = route_direct{"
  echo "        child = \"main\""
  echo "    }"
  echo "}"
} > "$TMP_CONF"

# === Verificação e atualização do arquivo final ===
if [[ ! -f "$PROXY_CONF" ]] || ! cmp -s "$TMP_CONF" "$PROXY_CONF"; then
  log "Arquivo de configuração alterado ou inexistente. Atualizando..."
  mv "$TMP_CONF" "$PROXY_CONF"
  chmod 644 "$PROXY_CONF"

  if systemctl list-units --type=service | grep -q "$SERVICE_NAME"; then
    log "Reiniciando serviço: $SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
  else
    log "Aviso: serviço '$SERVICE_NAME' não encontrado. Pulei reinício."
  fi
else
  log "Configuração já atualizada. Nenhuma mudança detectada."
  rm -f "$TMP_CONF"
fi

log "proxy.lua final:"
cat "$PROXY_CONF"

log "Script concluído com sucesso."
