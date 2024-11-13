#!/bin/bash

echo "Sanal ortam oluşturuluyor..."
python3 -m venv venv

echo "Sanal ortam aktive ediliyor..."
source venv/bin/activate

echo "Gerekli paketler yükleniyor..."
pip install -r requirements.txt

echo "main.py çalışıyor..."
python3 main.py

