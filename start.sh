#!/bin/bash
source venv/bin/activate
export FLASK_APP=wirehound.py
export FLASK_ENV=development
flask run
