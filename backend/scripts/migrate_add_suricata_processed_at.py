"""
Script de migração: adiciona coluna processed_at na tabela suricata_alerts
para controle de bloqueio automático (evitar reprocessamento).

Execute a partir da raiz do backend: python scripts/migrate_add_suricata_processed_at.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from db.session import SessionLocal


def migrate():
    """Adiciona coluna processed_at em suricata_alerts se não existir."""
    db = SessionLocal()
    try:
        result = db.execute(text("""
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_schema = DATABASE() AND table_name = 'suricata_alerts' AND column_name = 'processed_at'
        """))
        if result.scalar() > 0:
            print("Coluna suricata_alerts.processed_at já existe. Nenhuma alteração necessária.")
            return

        print("Adicionando coluna processed_at em suricata_alerts...")
        db.execute(text("""
            ALTER TABLE suricata_alerts
            ADD COLUMN processed_at DATETIME DEFAULT NULL
            COMMENT 'Data/hora em que foi processado para bloqueio automático'
            AFTER raw_log_data
        """))
        db.execute(text("""
            ALTER TABLE suricata_alerts
            ADD KEY idx_suricata_alerts_processed_at (processed_at)
        """))
        db.commit()
        print("Coluna processed_at e índice criados com sucesso.")
    except Exception as e:
        db.rollback()
        print(f"Erro na migração: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
