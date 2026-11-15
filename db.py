"""DB 接続とテーブル作成"""
import os

import psycopg

# Render では DATABASE_URL が自動で設定されます（render.yaml を参照）
# ローカルで試すときは、例えば次のように設定してください:
#   postgresql://postgres:postgres@localhost:5432/volunteer
DATABASE_URL = os.environ.get("DATABASE_URL")


def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("環境変数 DATABASE_URL が設定されていません")
    return psycopg.connect(DATABASE_URL)


def init_db():
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS volunteers (
                id         SERIAL PRIMARY KEY,
                name       VARCHAR(100) NOT NULL,
                email      VARCHAR(255) NOT NULL UNIQUE,
                -- 【脆弱性②】本来は password_hash を保存する列。今は平文が入る
                password   VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
