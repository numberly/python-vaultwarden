import os
import shutil
from time import sleep

def start_docker():
    shutil.copytree("tests/fixtures/server", "tests/e2e/temp/", dirs_exist_ok=True)
    os.system("docker compose -f tests/e2e/compose.yaml up -d")
    sleep(1) 

def stop_docker():
    os.system("docker compose -f tests/e2e/compose.yaml down")
    try:
        shutil.rmtree("tests/e2e/temp")
    except FileNotFoundError:
        pass