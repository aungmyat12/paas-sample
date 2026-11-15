"""
⚠ 脆弱性学習用のテストアプリです ⚠
わざと脆弱にした箇所が 6 つあります（【脆弱性①】〜【脆弱性⑥】で検索してください）。
各箇所に「❌ 脆弱な書き方」と「✅ 正しい書き方」を並べて書いています。

- 本物のパスワードやメールアドレスは使わないでください
- 攻撃を試すのは、自分でデプロイしたこのアプリだけにしてください
- テストが終わったら Render のサービスを削除してください
"""
import os

from flask import Flask, redirect, render_template, request, session, url_for

from db import get_conn, init_db

app = Flask(__name__)

# ------------------------------------------------------------
# 【脆弱性⑤】固定の弱い SECRET_KEY
# ------------------------------------------------------------
# ❌ キーをコードに直書きしている。しかも推測しやすい。
#    このキーを知っている人は、セッション Cookie を偽造して
#    「volunteer_id = 1 の人」としてログインできてしまう。
app.secret_key = "secret"
#
# ✅ 正しい書き方：環境変数からランダムな値を読み込む
# app.secret_key = os.environ["SECRET_KEY"]

# 起動時にテーブルを作る（なければ）
init_db()


@app.route("/")
def welcome():
    # ログインしていなければログイン画面へ
    if "volunteer_id" not in session:
        return redirect(url_for("login"))

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT name, email FROM volunteers WHERE id = %s",
            (session["volunteer_id"],),
        )
        row = cur.fetchone()

    if row is None:
        session.clear()
        return redirect(url_for("login"))

    # 名前の表示方法は templates/welcome.html の【脆弱性④】を見てください
    return render_template("welcome.html", name=row[0], email=row[1])


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not name or not email or not password:
            error = "すべての項目を入力してください"
        elif len(password) < 8:
            error = "パスワードは8文字以上にしてください"
        else:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT 1 FROM volunteers WHERE email = %s", (email,))
                if cur.fetchone():
                    error = "このメールアドレスはすでに登録されています"
                else:
                    # ------------------------------------------------
                    # 【脆弱性②】パスワードを平文で保存している
                    # ------------------------------------------------
                    # ❌ 入力されたパスワードをそのまま DB に入れている。
                    #    DB が漏れたら、全員のパスワードがそのまま読める。
                    cur.execute(
                        "INSERT INTO volunteers (name, email, password) VALUES (%s, %s, %s)",
                        (name, email, password),
                    )
                    #
                    # ✅ 正しい書き方：ハッシュ化してから保存する
                    # from werkzeug.security import generate_password_hash
                    # cur.execute(
                    #     "INSERT INTO volunteers (name, email, password) VALUES (%s, %s, %s)",
                    #     (name, email, generate_password_hash(password)),
                    # )
                    return redirect(url_for("login", registered=1))

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    message = "登録が完了しました。ログインしてください。" if request.args.get("registered") else None

    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")

        # ------------------------------------------------------------
        # 【脆弱性⑥】ログイン試行回数の制限がない
        # ------------------------------------------------------------
        # ❌ 何回失敗しても止めないので、パスワードを総当たりで試せる。
        # ✅ 正しい対策：同じメール / IP からの失敗回数を数えて、
        #    一定回数を超えたら一定時間ロックする（Flask-Limiter など）。

        with get_conn() as conn, conn.cursor() as cur:
            # --------------------------------------------------------
            # 【脆弱性①】SQLインジェクション
            # --------------------------------------------------------
            # ❌ 入力をそのまま文字列連結で SQL に埋め込んでいる。
            #    メール欄に  ' OR '1'='1' --  と入れると、
            #    WHERE 句が常に真になり、パスワードなしでログインできる。
            sql = (
                "SELECT id, name FROM volunteers "
                f"WHERE email = '{email}' AND password = '{password}'"
            )
            print("[DEBUG] 実行するSQL:", sql, flush=True)  # Render のログで確認できます
            try:
                cur.execute(sql)
                row = cur.fetchone()
            except Exception as e:  # 構文エラーになる入力もあるので
                conn.rollback()
                print("[DEBUG] SQLエラー:", e, flush=True)
                row = None
            #
            # ✅ 正しい書き方：プレースホルダ（%s）を使い、
            #    パスワードはハッシュで照合する
            # from werkzeug.security import check_password_hash
            # cur.execute("SELECT id, name, password FROM volunteers WHERE email = %s", (email,))
            # row = cur.fetchone()
            # if row and check_password_hash(row[2], password): ...ログイン成功

            if row:
                session["volunteer_id"] = row[0]
                return redirect(url_for("welcome"))

            # --------------------------------------------------------
            # 【脆弱性③】ユーザー列挙
            # --------------------------------------------------------
            # ❌ 「メールが存在しない」と「パスワードが違う」でメッセージを
            #    分けているので、登録済みのメールアドレスが外から分かる。
            cur.execute("SELECT 1 FROM volunteers WHERE email = %s", (email,))
            if cur.fetchone() is None:
                error = "このメールアドレスは登録されていません"
            else:
                error = "パスワードが違います"
            #
            # ✅ 正しい書き方：どちらの場合も同じメッセージにする
            # error = "メールアドレスまたはパスワードが違います"

    return render_template("login.html", error=error, message=message)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # ローカルで試すとき用。
    # ⚠ debug=True は公開サーバーでは絶対に使わないこと
    #   （ブラウザからサーバー上で任意のコードを実行できてしまうため）
    app.run(host="127.0.0.1", port=5000)
