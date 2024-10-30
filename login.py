# login.py

import streamlit as st
import sqlite3
import bcrypt

# 데이터베이스 초기화 및 사용자 추가
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    # 테이블이 없으면 생성
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT
        )
    ''')

    # 기본 사용자 추가 (아이디: user1, 비밀번호: 1234)
    user = {
        "username": "user1",
        "password": "1234"
    }

    # 비밀번호 해시 생성
    password_hash = bcrypt.hashpw(user["password"].encode(), bcrypt.gensalt()).decode()

    # 중복 방지를 위해 이미 있는지 확인
    c.execute("SELECT * FROM users WHERE username = ?", (user["username"],))
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (user["username"], password_hash))
        conn.commit()

    conn.close()

# 사용자 인증 함수
def authenticate_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    # 사용자 이름으로 사용자 정보 가져오기
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()

    if result:
        stored_password_hash = result[0]
        return bcrypt.checkpw(password.encode(), stored_password_hash.encode())
    return False

# Streamlit 앱 구성
def main():
    st.title("Login Page")

    # 로그인 폼
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if authenticate_user(username, password):
            st.success(f"Welcome {username}!")
            st.session_state['logged_in'] = True
        else:
            st.error("Invalid username or password")

if __name__ == '__main__':
    init_db()
    main()
