"""
Script de migração: cria a tabela suricata_alerts para armazenar os logs do Suricata.

Estrutura alinhada ao padrão do banco (incidents, institutions, etc.).
Execute a partir da raiz do backend: python scripts/migrate_add_suricata_alerts_table.py
"""

import sys
import os

# Garantir que o backend está no path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from db.session import SessionLocal

def migrate():
    """Cria a tabela suricata_alerts se não existir."""
    db = SessionLocal()
    try:
        # Verificar se a tabela já existe
        result = db.execute(text("""
            SELECT COUNT(*) FROM information_schema.tables 
            WHERE table_schema = DATABASE() AND table_name = 'suricata_alerts'
        """))
        exists = result.scalar() > 0
        if exists:
            print("Tabela suricata_alerts já existe. Nenhuma alteração necessária.")
            return

        print("Criando tabela suricata_alerts...")
        db.execute(text("""
            CREATE TABLE suricata_alerts (
                id INT(11) NOT NULL AUTO_INCREMENT,
                institution_id INT(11) NOT NULL COMMENT 'ID da instituição à qual o alerta pertence',
                detected_at DATETIME NOT NULL COMMENT 'Data/hora da detecção (timestamp do Suricata)',
                signature VARCHAR(500) NOT NULL COMMENT 'Assinatura/mensagem do alerta',
                signature_id VARCHAR(50) DEFAULT NULL COMMENT 'SID da regra Suricata',
                severity ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL DEFAULT 'MEDIUM' COMMENT 'Severidade do alerta',
                src_ip VARCHAR(45) DEFAULT NULL COMMENT 'IP de origem',
                dest_ip VARCHAR(45) DEFAULT NULL COMMENT 'IP de destino',
                src_port VARCHAR(20) DEFAULT NULL COMMENT 'Porta de origem',
                dest_port VARCHAR(20) DEFAULT NULL COMMENT 'Porta de destino',
                protocol VARCHAR(20) DEFAULT NULL COMMENT 'Protocolo (TCP, UDP, etc.)',
                category VARCHAR(255) DEFAULT NULL COMMENT 'Categoria do alerta',
                raw_log_data TEXT DEFAULT NULL COMMENT 'Dados brutos do alerta em JSON',
                processed_at DATETIME DEFAULT NULL COMMENT 'Data/hora em que foi processado para bloqueio automático',
                created_at DATETIME DEFAULT NULL COMMENT 'Data/hora de inserção no banco',
                updated_at DATETIME DEFAULT NULL COMMENT 'Data/hora da última atualização',
                PRIMARY KEY (id),
                KEY idx_suricata_alerts_institution_id (institution_id),
                KEY idx_suricata_alerts_detected_at (detected_at),
                KEY idx_suricata_alerts_severity (severity),
                KEY idx_suricata_alerts_src_ip (src_ip),
                KEY idx_suricata_alerts_dest_ip (dest_ip),
                KEY idx_suricata_alerts_processed_at (processed_at),
                CONSTRAINT suricata_alerts_ibfk_1 FOREIGN KEY (institution_id) REFERENCES institutions (id)
            ) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci
        """))
        db.commit()
        print("Tabela suricata_alerts criada com sucesso.")
    except Exception as e:
        db.rollback()
        print(f"Erro ao criar tabela: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    migrate()
