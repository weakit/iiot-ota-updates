import base64
import hashlib
import os
import sched
import shutil
import subprocess
import time
import zipfile

import requests as r
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# check for updates every 1 minute, for demonstration only
# this should be done a few times a day at most
UPDATE_INTERVAL = 10
PUBLIC_KEY = "keys/public.pem"
SERVER_ENDPOINT = "http://localhost:8000/"

scheduler = sched.scheduler(time.time, time.sleep)
process = None


def check_hash(file, hash):
    """
    Checks the sha256 hash of a given file to see if it is the same.
    :param file:
    :return:
    """

    with open(file, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    return file_hash == hash


def verify_signature(file_path, b64sig):
    """
    Verifies the signature of a file using the public key.

    :param file_path: The path to the file to verify.
    :param b64sig: The base64 encoded signature.

    :return: True if the signature is valid, False otherwise.
    """
    with open(os.path.join(os.path.dirname(__file__), PUBLIC_KEY), "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )

    with open(file_path, "rb") as file:
        file_data = file.read()

    signature = base64.b64decode(b64sig)

    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        print(e)
        return False


def end_process():
    global process

    if process is not None:
        print("Stopping process.")
        process.terminate()
        process.wait()

    process = None


def start_process():
    global process

    # ensure the program exists before trying to start
    if not os.path.exists("program/index.py"):
        print("No version of the program is available locally to run.")
        return

    print("Starting process.")
    process = subprocess.Popen(["python", "program/index.py"])


def download_manifest(ver="latest"):
    """
    Checks for updates by downloading the manifest file from the server.

    :param ver: download a specific version if required
    :return: True if there are updates and the manifest was updated, otherwise False
    """

    # read the current manifest if it exists
    current_version = None

    if os.path.exists("current"):
        with open("current", "r") as f:
            current_manifest = f.read()
            current_version = current_manifest.splitlines()[0]

    print(f"Current version is {current_version}.")

    manifest_location = SERVER_ENDPOINT + f"deployments/{ver}"

    # ensure connection to API is feasible
    try:
        r.get(SERVER_ENDPOINT)
    except r.exceptions.ConnectionError:
        print("Could not connect to the server. Aborting Update.")
        return False

    # download the manifest
    manifest_rest = r.get(manifest_location)
    manifest = manifest_rest.text

    if current_version == manifest.splitlines()[0]:
        print("No updates available.")
        return False

    manifest_sig_rest = r.get(manifest_location + '.sig')
    manifest_sig = manifest_sig_rest.text

    # save the current manifest
    with open("current", "wb") as f:
        f.write(manifest.encode())

    # verify manifest is signed
    assert verify_signature("current", manifest_sig)

    return True


def download_program():
    """
    Downloads and replaces the program with the current manifest.
    """

    with open("current", "r") as f:
        manifest = f.read()

    lines = manifest.splitlines()

    print(f"Downloading version {lines[0]}.")

    program = lines[2].split()
    chunks = [x.split() for x in lines[3:]]

    # Create temp folder if it does not exist
    if not os.path.exists("temp"):
        os.makedirs("temp")

    print(f"Attempting to download {len(chunks)} chunks.")

    # download all chunks to temp folder
    for chunk in chunks:
        chunk_hash = chunk[0]
        chunk_name = chunk[1]

        chunk_res = r.get(SERVER_ENDPOINT + f"deployment_data/{chunk_name}")

        with open(f"temp/{chunk_name}", "wb") as f:
            f.write(chunk_res.content)

        # check hash
        assert check_hash(f"temp/{chunk_name}", chunk_hash)

    print("Chunks OK.")

    print("Attempting to replace program.")
    # merge all chunks to create the program zip
    with open("temp/program.zip", "wb") as f:
        for chunk in chunks:
            with open(f"temp/{chunk[1]}", "rb") as chunk_file:
                f.write(chunk_file.read())

    assert check_hash("temp/program.zip", program[1])

    # delete the program folder if it exists
    if os.path.exists("program"):
        shutil.rmtree('program')

    # extract program.zip into the program folder
    with zipfile.ZipFile("temp/program.zip", "r") as zip_ref:
        zip_ref.extractall("program")

    print("Program OK.")

    # delete the temp folder
    shutil.rmtree('temp')


def update():
    print("\nChecking for updates.")

    if download_manifest():
        end_process()
        download_program()

    if process is None:
        start_process()

    scheduler.enter(UPDATE_INTERVAL, 1, update)


def main():
    update()

    scheduler.enter(UPDATE_INTERVAL, 1, update)
    scheduler.run()


if __name__ == "__main__":
    main()
