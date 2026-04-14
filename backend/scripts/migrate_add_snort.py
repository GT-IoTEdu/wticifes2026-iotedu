"""
Script de migração: adiciona Snort à API.
1. Adiciona snort_base_url e snort_key na tabela institutions.
2. Cria a tabela snort_alerts (estrutura igual à suricata_alerts).

Execute a partir da raiz do backend: python scripts/migrate_add_snort.py
"""

import sys
import os
from pathlib import Path

backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from sqlalchemy import text, inspect
from db.session import SessionLocal


def migrate_institution_columns(db):
    """Adiciona snort_base_url e snort_key em institutions se não existirem."""
    inspector = inspect(db.get_bind())
    columns = [col["name"] for col in inspector.get_columns("institutions")]
    if "snort_base_url" in columns and "snort_key" in columns:
        print("Colunas snort_base_url e snort_key já existem em institutions.")
        return
    if "snort_base_url" not in columns:
        db.execute(text("""
            ALTER TABLE institutions
            ADD COLUMN snort_base_url VARCHAR(500) NULL
            COMMENT 'URL base para conectar no Snort'
        """))
        db.commit()
        print("Coluna snort_base_url adicionada em institutions.")
    if "snort_key" not in columns:
        db.execute(text("""
            ALTER TABLE institutions
            ADD COLUMN snort_key VARCHAR(500) NULL
            COMMENT 'Chave de acesso ao Snort'
        """))
        db.commit()
        print("Coluna snort_key adicionada em institutions.")


def migrate_snort_alerts_table(db):
    """Cria a tabela snort_alerts se não existir."""
    result = db.execute(text("""
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = 'snort_alerts'
    """))
    if result.scalar() > 0:
        print("Tabela snort_alerts já existe. Nenhuma alteração necessária.")
        return
    print("Criando tabela snort_alerts...")
    db.execute(text("""
        CREATE TABLE snort_alerts (
            id INT(11) NOT NULL AUTO_INCREMENT,
            institution_id INT(11) NOT NULL COMMENT 'ID da instituição à qual o alerta pertence',
            detected_at DATETIME NOT NULL COMMENT 'Data/hora da detecção (timestamp do Snort)',
            signature VARCHAR(500) NOT NULL COMMENT 'Assinatura/mensagem do alerta',
            signature_id VARCHAR(50) DEFAULT NULL COMMENT 'SID da regra Snort',
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
            KEY idx_snort_alerts_institution_id (institution_id),
            KEY idx_snort_alerts_detected_at (detected_at),
            KEY idx_snort_alerts_severity (severity),
            KEY idx_snort_alerts_src_ip (src_ip),
            KEY idx_snort_alerts_dest_ip (dest_ip),
            KEY idx_snort_alerts_processed_at (processed_at),
            CONSTRAINT snort_alerts_ibfk_1 FOREIGN KEY (institution_id) REFERENCES institutions (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci
    """))
    db.commit()
    print("Tabela snort_alerts criada com sucesso.")


def migrate():
    db = SessionLocal()
    try:
        migrate_institution_columns(db)
        migrate_snort_alerts_table(db)
    except Exception as e:
        db.rollback()
        print(f"Erro na migração: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    print("=" * 60)
    print("MIGRAÇÃO: Adicionar Snort (institutions + snort_alerts)")
    print("=" * 60)
    migrate()
    print("\nMigração concluída.")
