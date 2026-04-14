#!/bin/bash

# Limpar containers antigos
docker rm -f servidor_alvo atacante 2>/dev/null

# Criar container servidor_alvo (sem --mac-address pois será sobrescrito)
docker run -d --name servidor_alvo --hostname servidor_alvo \
    --network none \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    servidor_alvo:latest sleep infinity


sudo ip link add veth-host-01 type veth peer name veth-cont-01

# Definir MAC address na interface que irá para o container
sudo ip link set veth-cont-01 address 92:d0:c6:0a:29:32

# Configurar bridge
sudo ip link set veth-host-01 master bridge-tap
sudo ip link set veth-host-01 up
CPID=$(docker inspect -f '{{.State.Pid}}' servidor_alvo)
sudo ip link set veth-cont-01 netns "${CPID}"
docker exec -d servidor_alvo ./entrypoint.sh




sleep 10
# Obter IP
SERVER_ALVO=$(docker exec servidor_alvo ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')


echo "IP do servidor: $SERVER_ALVO"

# Container atacante
docker run -d --name atacante --hostname atacante \
    --network none \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    -e SERVER_IP="$SERVER_ALVO" \
    atacante:latest sleep infinity


sudo ip link add veth-host-02 type veth peer name veth-cont-02
sudo ip link set veth-cont-02 address 92:d0:c6:0a:29:33
sudo ip link set veth-host-02 master bridge-tap
sudo ip link set veth-host-02 up
C02PID=$(docker inspect -f '{{.State.Pid}}' atacante)
sudo ip link set veth-cont-02 netns "${C02PID}"
docker exec -it atacante ./entrypoint.sh
