import ipaddress
import struct

from grader.iputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        destino = ipaddress.IPv4Address(dest_addr)
        for rede, next_hop in self.tabela_encaminhamento:
            if destino in rede:
                return next_hop
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        
        self.tabela_encaminhamento = [
            (ipaddress.IPv4Network(cidr, strict=False), next_hop) for cidr, next_hop in tabela
        ]


    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Monta o datagrama IP e envia para o próximo salto.
        """
        next_hop = self._next_hop(dest_addr)
        
        if not next_hop:
            return  # Sem rota disponível

        src_addr = self.meu_endereco
        total_len = 20 + len(segmento)  # Tamanho do cabeçalho IP + segmento TCP
        identification = 0
        flags_frag_offset = 0
        ttl = 64
        proto = IPPROTO_TCP
        
        # Cabeçalho IP sem checksum
        header_sem_checksum = struct.pack(
            '!BBHHHBBHII', 
            0x45, 0, total_len, identification, flags_frag_offset, ttl, proto, 
            0, int(ipaddress.IPv4Address(src_addr)), int(ipaddress.IPv4Address(dest_addr))
        )

        # Calcula o checksum do cabeçalho
        checksum = calc_checksum(header_sem_checksum)
        
        # Cabeçalho IP completo com checksum
        header_completo = struct.pack(
            '!BBHHHBBHII', 
            0x45, 0, total_len, identification, flags_frag_offset, ttl, proto, 
            checksum, int(ipaddress.IPv4Address(src_addr)), int(ipaddress.IPv4Address(dest_addr))
        )
        
        # Datagrama completo (cabeçalho + segmento TCP)
        datagrama = header_completo + segmento
        
        self.enlace.enviar(datagrama, next_hop)

# Commit vazio