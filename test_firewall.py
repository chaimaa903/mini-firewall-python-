#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from scapy.all import IP, ICMP, TCP, UDP, Ether
from firewall import RuleManager, PacketFilter


class TestFirewall(unittest.TestCase):
    def setUp(self):
        # Créer un gestionnaire de règles avec des règles de test
        self.rule_manager = RuleManager("config/rules.json")
        self.rule_manager.rules = {
            "allow": [
                {"protocol": "tcp", "comment": "Autoriser tout le trafic TCP"}
            ],
            "block": [
                {"protocol": "icmp", "comment": "Bloquer les pings ICMP"}
            ]
        }

        # Créer un filtre de paquets
        self.packet_filter = PacketFilter(self.rule_manager)

    def test_tcp_packet_allowed(self):
        # Créer un paquet TCP
        tcp_packet = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80)

        # Tester le filtrage
        is_allowed, rule_matched, _ = self.packet_filter.filter_packet(tcp_packet)

        # Vérifier que le paquet est autorisé
        self.assertTrue(is_allowed)
        self.assertEqual(rule_matched["protocol"], "tcp")

    def test_icmp_packet_blocked(self):
        # Créer un paquet ICMP (ping)
        icmp_packet = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / ICMP()

        # Tester le filtrage
        is_allowed, rule_matched, _ = self.packet_filter.filter_packet(icmp_packet)

        # Vérifier que le paquet est bloqué
        self.assertFalse(is_allowed)
        self.assertEqual(rule_matched["protocol"], "icmp")

    def test_udp_packet_blocked_by_default(self):
        # Créer un paquet UDP
        udp_packet = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / UDP(sport=12345, dport=53)

        # Tester le filtrage
        is_allowed, rule_matched, _ = self.packet_filter.filter_packet(udp_packet)

        # Vérifier que le paquet est bloqué par défaut (aucune règle ne correspond)
        self.assertFalse(is_allowed)
        self.assertIsNone(rule_matched)

    def test_specific_ip_rule(self):
        # Ajouter une règle pour bloquer une IP spécifique
        self.rule_manager.rules["block"].append({
            "src_ip": "10.0.0.1",
            "comment": "Bloquer une IP spécifique"
        })

        # Créer un paquet TCP depuis l'IP bloquée
        tcp_packet = Ether() / IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80)

        # Tester le filtrage
        is_allowed, rule_matched, _ = self.packet_filter.filter_packet(tcp_packet)

        # Vérifier que le paquet est bloqué malgré la règle TCP générale
        self.assertFalse(is_allowed)
        self.assertEqual(rule_matched["src_ip"], "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
