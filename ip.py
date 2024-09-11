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
        dscp, ecn, identification, flags_frag_offset, frag_offset, ttl, proto, \
        src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if ttl <= 1:
            # TTL chegou a zero, descarta o datagrama e gera ICMP Time Exceeded
            self._enviar_icmp_time_exceeded(src_addr, datagrama)
            return

        ttl -= 1
        new_header = struct.pack(
            '!BBHHHBBHII',
            0x45, 0, len(datagrama), identification, flags_frag_offset, ttl, proto,
            0, int(ipaddress.IPv4Address(src_addr)), int(ipaddress.IPv4Address(dst_addr))
        )
        checksum = calc_checksum(new_header)
        new_header = struct.pack(
            '!BBHHHBBHII',
            0x45, 0, len(datagrama), identification, flags_frag_offset, ttl, proto,
            checksum, int(ipaddress.IPv4Address(src_addr)), int(ipaddress.IPv4Address(dst_addr))
        )
        
        datagrama = new_header + payload
        next_hop = self._next_hop(dst_addr)
        self.enlace.enviar(datagrama, next_hop)
        
    def _enviar_icmp_time_exceeded(self, src_addr, datagrama_original):
        """
        Gera e envia uma mensagem ICMP Time Exceeded de volta ao remetente.
        """
        # Cabeçalho ICMP: Tipo (11), Código (0), Checksum (0 inicialmente)
        tipo = 11  # Time Exceeded
        codigo = 0  # TTL Expired in Transit
        checksum_icmp = 0  # Inicialmente 0 para calcular
        reserved = 0  # Reservado, geralmente 0

        # O cabeçalho IP original tem 20 bytes, e queremos os primeiros 8 bytes do payload
        original_header = datagrama_original[:20]
        original_payload = datagrama_original[20:28]  # Pegando os primeiros 8 bytes do payload original

        # ICMP Payload: 20 bytes do cabeçalho IP original + primeiros 8 bytes do payload
        icmp_payload = original_header + original_payload

        # Montando o cabeçalho ICMP sem o checksum
        icmp_header = struct.pack('!BBHI', tipo, codigo, checksum_icmp, reserved)

        # Calculando o checksum ICMP
        checksum_icmp = calc_checksum(icmp_header + icmp_payload)

        # Montando o cabeçalho ICMP com o checksum correto
        icmp_header = struct.pack('!BBHI', tipo, codigo, checksum_icmp, reserved)

        # Criando o datagrama ICMP (cabeçalho + payload)
        icmp_message = icmp_header + icmp_payload

        # Agora precisamos criar um novo cabeçalho IP para o datagrama ICMP
        total_len = 20 + len(icmp_message)  # Tamanho do cabeçalho IP + ICMP
        identification = 0
        flags_frag_offset = 0
        ttl = 64
        proto = IPPROTO_ICMP  # Protocolo ICMP
        
        src_ip = self.meu_endereco
        dst_ip = src_addr  # Enviamos de volta para o remetente (src_addr)

        # Cabeçalho IP sem o checksum
        header_sem_checksum = struct.pack(
            '!BBHHHBBHII', 
            0x45, 0, total_len, identification, flags_frag_offset, ttl, proto, 
            0, int(ipaddress.IPv4Address(src_ip)), int(ipaddress.IPv4Address(dst_ip))
        )

        # Calculando o checksum do cabeçalho IP
        checksum_ip = calc_checksum(header_sem_checksum)

        # Cabeçalho IP completo com o checksum
        header_completo = struct.pack(
            '!BBHHHBBHII', 
            0x45, 0, total_len, identification, flags_frag_offset, ttl, proto, 
            checksum_ip, int(ipaddress.IPv4Address(src_ip)), int(ipaddress.IPv4Address(dst_ip))
        )

        # Datagrama completo (cabeçalho IP + mensagem ICMP)
        datagrama_icmp = header_completo + icmp_message

        # Enviar o datagrama de volta ao remetente
        next_hop = self._next_hop(dst_ip)
        self.enlace.enviar(datagrama_icmp, next_hop)

    def _next_hop(self, dest_addr):
        """
        Encontra o próximo salto com base no prefixo mais longo.
        """
        destino = ipaddress.IPv4Address(dest_addr)
        melhor_cidr = None
        next_hop = None

        for rede, hop in self.tabela_encaminhamento:
            if destino in rede:
                if not melhor_cidr or rede.prefixlen > melhor_cidr.prefixlen:
                    melhor_cidr = rede
                    next_hop = hop
        
        return next_hop

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
