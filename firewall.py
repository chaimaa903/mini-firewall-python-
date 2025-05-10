#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import logging
from scapy.all import sniff, IP, ICMP, TCP, UDP, Raw, send, sr1
import threading

# Vérifier si on est sur Windows pour utiliser pydivert
is_windows = sys.platform.startswith('win')
if is_windows:
    try:
        import pydivert
    except ImportError:
        print("PyDivert n'est pas installé. Installez-le avec: pip install pydivert")
        print("Le blocage actif ne sera pas disponible.")
        is_windows = False


class PacketSniffer:
    def __init__(self, interface=None):
        self.interface = interface
        self.stop_sniffing = False
        self.sniff_thread = None

    def start_sniffing(self, callback):
        """Démarre la capture de paquets et appelle callback pour chaque paquet"""

        def _sniff_packets():
            sniff(
                iface=self.interface,
                prn=callback,
                store=0,
                stop_filter=lambda x: self.stop_sniffing
            )

        self.stop_sniffing = False
        self.sniff_thread = threading.Thread(target=_sniff_packets)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        print(f"[+] Sniffing démarré{' sur ' + self.interface if self.interface else ''}")

    def stop(self):
        """Arrête la capture de paquets"""
        self.stop_sniffing = True
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2)
        print("[+] Sniffing arrêté")


class RuleManager:
    def __init__(self, rules_file="config/rules.json"):
        self.rules_file = rules_file
        # Créer le dossier config s'il n'existe pas
        os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
        self.rules = self.load_rules()

    def load_rules(self):
        """Charge les règles depuis le fichier JSON"""
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    return json.load(f)
            else:
                # Règles par défaut si le fichier n'existe pas
                default_rules = {
                    "allow": [
                        {"protocol": "tcp", "comment": "Autoriser tout le trafic TCP"}
                    ],
                    "block": [
                        {"protocol": "icmp", "comment": "Bloquer les pings ICMP"}
                    ]
                }
                # Sauvegarder les règles par défaut
                with open(self.rules_file, 'w') as f:
                    json.dump(default_rules, f, indent=4)
                return default_rules
        except Exception as e:
            print(f"Erreur lors du chargement des règles: {e}")
            return {"allow": [], "block": []}

    def save_rules(self):
        """Sauvegarde les règles dans le fichier JSON"""
        try:
            with open(self.rules_file, 'w') as f:
                json.dump(self.rules, f, indent=4)
            print(f"[+] Règles sauvegardées dans {self.rules_file}")
        except Exception as e:
            print(f"Erreur lors de la sauvegarde des règles: {e}")

    def match_rule(self, packet):
        """
        Vérifie si un paquet correspond à une règle
        Retourne (is_allowed, rule_matched) où:
        - is_allowed: True si le paquet est autorisé, False s'il doit être bloqué
        - rule_matched: La règle qui a été appliquée ou None
        """
        # Vérifier d'abord les règles de blocage
        for rule in self.rules.get("block", []):
            if self._packet_matches_rule(packet, rule):
                return False, rule

        # Ensuite vérifier les règles d'autorisation
        for rule in self.rules.get("allow", []):
            if self._packet_matches_rule(packet, rule):
                return True, rule

        # Par défaut, bloquer le paquet si aucune règle ne correspond
        return False, None

    def _packet_matches_rule(self, packet, rule):
        """Vérifie si un paquet correspond à une règle spécifique"""
        # Vérifier le protocole
        if "protocol" in rule:
            if rule["protocol"].lower() == "icmp" and ICMP not in packet:
                return False
            elif rule["protocol"].lower() == "tcp" and TCP not in packet:
                return False
            elif rule["protocol"].lower() == "udp" and UDP not in packet:
                return False

        # Vérifier l'adresse IP source
        if "src_ip" in rule and IP in packet:
            if packet[IP].src != rule["src_ip"]:
                return False

        # Vérifier l'adresse IP destination
        if "dst_ip" in rule and IP in packet:
            if packet[IP].dst != rule["dst_ip"]:
                return False

        # Vérifier le port source (pour TCP/UDP)
        if "src_port" in rule:
            if (TCP in packet and packet[TCP].sport != int(rule["src_port"])) or \
                    (UDP in packet and packet[UDP].sport != int(rule["src_port"])):
                return False

        # Vérifier le port destination (pour TCP/UDP)
        if "dst_port" in rule:
            if (TCP in packet and packet[TCP].dport != int(rule["dst_port"])) or \
                    (UDP in packet and packet[UDP].dport != int(rule["dst_port"])):
                return False

        # Si toutes les conditions sont satisfaites, le paquet correspond à la règle
        return True


class PacketFilter:
    def __init__(self, rule_manager):
        self.rule_manager = rule_manager

    def filter_packet(self, packet):
        """
        Filtre un paquet selon les règles
        Retourne (is_allowed, rule_matched, packet_info) où:
        - is_allowed: True si le paquet est autorisé, False s'il doit être bloqué
        - rule_matched: La règle qui a été appliquée ou None
        - packet_info: Informations sur le paquet pour le logging
        """
        packet_info = self._extract_packet_info(packet)
        is_allowed, rule_matched = self.rule_manager.match_rule(packet)

        return is_allowed, rule_matched, packet_info
    def _extract_packet_info(self, packet):
        """Extrait les informations pertinentes d'un paquet pour le logging"""
        info = {
            "timestamp": time.time(),
            "protocol": "unknown"
        }
        
        if IP in packet:
            info["src_ip"] = packet[IP].src
            info["dst_ip"] = packet[IP].dst
        
            if TCP in packet:
                info["protocol"] = "tcp"
                info["src_port"] = packet[TCP].sport
                info["dst_port"] = packet[TCP].dport
                # Convertir les drapeaux TCP en chaîne de caractères pour la sérialisation JSON
                info["flags"] = str(packet[TCP].flags)
            elif UDP in packet:
                info["protocol"] = "udp"
                info["src_port"] = packet[UDP].sport
                info["dst_port"] = packet[UDP].dport
            elif ICMP in packet:
                info["protocol"] = "icmp"
                info["icmp_type"] = packet[ICMP].type
                info["icmp_code"] = packet[ICMP].code
        
        return info
    
class PacketBlocker:
    def __init__(self):
        self.is_windows = is_windows
        self.divert = None

        if self.is_windows:
            try:
                # Initialiser PyDivert pour le blocage actif sous Windows
                self.divert = pydivert.WinDivert()
                print("[+] PyDivert initialisé pour le blocage actif")
            except Exception as e:
                print(f"Erreur lors de l'initialisation de PyDivert: {e}")
                self.is_windows = False

    def block_packet(self, packet, packet_info):
        """Bloque un paquet selon la plateforme"""
        if self.is_windows and self.divert:
            # Blocage actif avec PyDivert sous Windows
            # Note: Cette méthode est simplifiée, en pratique il faudrait
            # configurer des règles de filtrage plus précises avec PyDivert
            return True
        else:
            # Méthode alternative: envoyer un TCP RST pour les connexions TCP
            if packet_info["protocol"] == "tcp" and IP in packet and TCP in packet:
                try:
                    # Créer un paquet RST
                    rst = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          TCP(dport=packet[TCP].sport, sport=packet[TCP].dport,
                              flags="R", seq=packet[TCP].ack)
                    send(rst, verbose=0)
                    return True
                except Exception as e:
                    print(f"Erreur lors de l'envoi du paquet RST: {e}")

            # Pour les autres protocoles, on ne peut pas bloquer activement sans accès bas niveau
            return False


class LoggerJSON:
    def __init__(self, log_file="logs/events.json"):
        self.log_file = log_file
        # Créer le dossier logs s'il n'existe pas
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

        # Configurer le logger
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("FirewallLogger")

        # Créer le fichier de log s'il n'existe pas
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                f.write("[]")

    def log_event(self, event):
        """Écrit un événement dans le fichier de log JSON"""
        try:
            # Lire les logs existants
            with open(self.log_file, 'r') as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []

            # Ajouter le nouvel événement
            logs.append(event)

            # Écrire les logs mis à jour
            with open(self.log_file, 'w') as f:
                json.dump(logs, f, indent=4)

            # Aussi logger dans la console
            self.logger.info(f"Event logged: {json.dumps(event)}")

            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de l'écriture du log: {e}")
            return False


class CLIInterface:
    def __init__(self, firewall):
        self.firewall = firewall

    def run(self):
        """Interface utilisateur simple en ligne de commande"""
        print("=" * 50)
        print("Mini-SIEM Firewall - Interface de contrôle")
        print("=" * 50)

        while True:
            print("\nOptions:")
            print("1. Démarrer le firewall")
            print("2. Arrêter le firewall")
            print("3. Afficher les statistiques")
            print("4. Afficher/Modifier les règles")
            print("5. Quitter")

            choice = input("\nChoisissez une option (1-5): ")

            if choice == "1":
                self.firewall.run()
            elif choice == "2":
                self.firewall.stop()
            elif choice == "3":
                self.show_stats()
            elif choice == "4":
                self.manage_rules()
            elif choice == "5":
                self.firewall.stop()
                print("Au revoir!")
                break
            else:
                print("Option invalide. Veuillez réessayer.")

    def show_stats(self):
        """Affiche les statistiques du firewall"""
        print("\n--- Statistiques du Firewall ---")
        print(f"Paquets analysés: {self.firewall.stats['packets_processed']}")
        print(f"Paquets autorisés: {self.firewall.stats['packets_allowed']}")
        print(f"Paquets bloqués: {self.firewall.stats['packets_blocked']}")
        print(f"Temps d'exécution: {time.time() - self.firewall.start_time:.2f} secondes")

    def manage_rules(self):
        """Interface pour afficher et modifier les règles"""
        print("\n--- Gestion des Règles ---")

        # Afficher les règles actuelles
        print("\nRègles d'autorisation:")
        for i, rule in enumerate(self.firewall.rule_manager.rules.get("allow", [])):
            print(f"{i + 1}. {json.dumps(rule)}")

        print("\nRègles de blocage:")
        for i, rule in enumerate(self.firewall.rule_manager.rules.get("block", [])):
            print(f"{i + 1}. {json.dumps(rule)}")

        # Options de modification
        print("\nOptions:")
        print("1. Ajouter une règle d'autorisation")
        print("2. Ajouter une règle de blocage")
        print("3. Supprimer une règle")
        print("4. Retour au menu principal")

        choice = input("\nChoisissez une option (1-4): ")

        if choice == "1":
            self.add_rule("allow")
        elif choice == "2":
            self.add_rule("block")
        elif choice == "3":
            self.delete_rule()
        elif choice == "4":
            return
        else:
            print("Option invalide.")

    def add_rule(self, rule_type):
        """Ajoute une nouvelle règle"""
        print(f"\nAjouter une règle de {rule_type}")

        rule = {}

        # Demander les détails de la règle
        protocol = input("Protocole (tcp/udp/icmp): ").lower()
        if protocol in ["tcp", "udp", "icmp"]:
            rule["protocol"] = protocol
        else:
            print("Protocole invalide.")
            return

        # Pour TCP et UDP, demander les ports
        if protocol in ["tcp", "udp"]:
            src_port = input("Port source (laissez vide pour ignorer): ")
            if src_port:
                try:
                    rule["src_port"] = int(src_port)
                except ValueError:
                    print("Port invalide.")
                    return

            dst_port = input("Port destination (laissez vide pour ignorer): ")
            if dst_port:
                try:
                    rule["dst_port"] = int(dst_port)
                except ValueError:
                    print("Port invalide.")
                    return

        # Demander les adresses IP
        src_ip = input("IP source (laissez vide pour ignorer): ")
        if src_ip:
            rule["src_ip"] = src_ip

        dst_ip = input("IP destination (laissez vide pour ignorer): ")
        if dst_ip:
            rule["dst_ip"] = dst_ip

        # Ajouter un commentaire
        comment = input("Commentaire (optionnel): ")
        if comment:
            rule["comment"] = comment

        # Ajouter la règle
        if rule_type not in self.firewall.rule_manager.rules:
            self.firewall.rule_manager.rules[rule_type] = []

        self.firewall.rule_manager.rules[rule_type].append(rule)
        self.firewall.rule_manager.save_rules()

        print(f"Règle de {rule_type} ajoutée avec succès.")

    def delete_rule(self):
        """Supprime une règle existante"""
        print("\nSupprimer une règle")

        # Afficher toutes les règles avec un index
        all_rules = []

        print("\nRègles d'autorisation:")
        for rule in self.firewall.rule_manager.rules.get("allow", []):
            all_rules.append(("allow", rule))
            print(f"{len(all_rules)}. ALLOW: {json.dumps(rule)}")

        print("\nRègles de blocage:")
        for rule in self.firewall.rule_manager.rules.get("block", []):
            all_rules.append(("block", rule))
            print(f"{len(all_rules)}. BLOCK: {json.dumps(rule)}")

        # Demander quelle règle supprimer
        try:
            index = int(input("\nEntrez le numéro de la règle à supprimer: ")) - 1

            if 0 <= index < len(all_rules):
                rule_type, rule = all_rules[index]
                self.firewall.rule_manager.rules[rule_type].remove(rule)
                self.firewall.rule_manager.save_rules()
                print("Règle supprimée avec succès.")
            else:
                print("Index invalide.")
        except ValueError:
            print("Entrée invalide.")


class Firewall:
    def __init__(self, interface=None):
        self.interface = interface
        self.rule_manager = RuleManager()
        self.sniffer = PacketSniffer(interface)
        self.filter = PacketFilter(self.rule_manager)
        self.blocker = PacketBlocker()
        self.logger = LoggerJSON()

        self.running = False
        self.start_time = 0
        self.stats = {
            "packets_processed": 0,
            "packets_allowed": 0,
            "packets_blocked": 0
        }

    def run(self):
        """Démarre le firewall"""
        if self.running:
            print("Le firewall est déjà en cours d'exécution.")
            return

        self.running = True
        self.start_time = time.time()
        self.sniffer.start_sniffing(self.apply_rules)
        print("[+] Firewall démarré")

    def stop(self):
        """Arrête le firewall"""
        if not self.running:
            print("Le firewall n'est pas en cours d'exécution.")
            return

        self.running = False
        self.sniffer.stop()
        print("[+] Firewall arrêté")

    def apply_rules(self, packet):
        """Applique les règles sur chaque paquet capturé"""
        self.stats["packets_processed"] += 1

        # Filtrer le paquet
        is_allowed, rule_matched, packet_info = self.filter.filter_packet(packet)

        # Préparer l'événement pour le logging
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": "ALLOW" if is_allowed else "BLOCK",
            "packet_info": packet_info
        }

        if rule_matched:
            event["rule_matched"] = rule_matched

        # Logger l'événement
        self.logger.log_event(event)

        # Mettre à jour les statistiques
        action_str = "[ALLOW]" if is_allowed else "[BLOCK]"
        protocol_str = packet_info['protocol'].upper()
        # Ajouter ces deux lignes ici pour mettre à jour les compteurs
        if is_allowed:
            self.stats["packets_allowed"] += 1
        else:
            self.stats["packets_blocked"] += 1
    # Ajouter des couleurs pour une meilleure visibilité (fonctionne dans la plupart des terminaux)
        if is_allowed:
             action_str = "\033[92m" + action_str + "\033[0m"  # Vert pour ALLOW
        else:
             action_str = "\033[91m" + action_str + "\033[0m"  # Rouge pour BLOCK
    
        print(f"{action_str} {protocol_str} ", end="")
    
        if "src_ip" in packet_info:
            print(f"from {packet_info['src_ip']}", end="")
            if "src_port" in packet_info:
                print(f":{packet_info['src_port']}", end="")
    
        print(f" to ", end="")
    
        if "dst_ip" in packet_info:
            print(f"{packet_info['dst_ip']}", end="")
            if "dst_port" in packet_info:
                print(f":{packet_info['dst_port']}", end="")
    
        print()
    
    # Afficher la règle appliquée
        if rule_matched:
            print(f"  └─ Règle appliquée: {json.dumps(rule_matched)}")
    
    # Tenter de bloquer le paquet si nécessaire
        if not is_allowed:
            blocked = self.blocker.block_packet(packet, packet_info)
            if blocked:
                print(f"  └─ Paquet bloqué activement")       


if __name__ == "__main__":
    # Détecter l'interface réseau
    interface = None
    if len(sys.argv) > 1:
        interface = sys.argv[1]

    # Créer et démarrer le firewall
    firewall = Firewall(interface)
    cli = CLIInterface(firewall)

    try:
        cli.run()
    except KeyboardInterrupt:
        print("\nInterruption détectée. Arrêt du firewall...")
        firewall.stop()
        print("Au revoir!")
