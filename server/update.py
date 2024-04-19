import base64
import datetime
import hashlib
import os
import shutil
import time
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import keys

PROGRAM_NAME = "iot"
CHUNK_SIZE = 32 * 1024
DEPLOYMENT_DATA_FOLDER = "deployment_data"
DEPLOYMENT_MANIFEST_FOLDER = "deployments"
PRIVATE_KEY = "keys/private.pem"
PUBLIC_KEY = "keys/public.pem"


def read_program():
    """
    Reads the contents of the program folder into memory, and them compresses it into a zip file.
    """

    # Read the contents of the program folder
    program_folder = os.path.join(os.path.dirname(__file__), "program")
    program_files = os.listdir(program_folder)

    # Create a zip file
    with zipfile.ZipFile("program.zip", "w", zipfile.ZIP_LZMA) as zip_file:
        for file in program_files:
            file_path = os.path.join(program_folder, file)
            zip_file.write(file_path, file)

    print("Packaged program.")

    # Return SHA256 hash of the zip file
    with open("program.zip", "rb") as zip_file:
        hash_object = hashlib.sha256(zip_file.read())
        print(f"program.zip {hash_object.hexdigest()}\n")
        return hash_object.hexdigest()


def split_data():
    """
    Splits the zip file into small chunks of data into the deployment folder.
    
    :return: The file prefix of the deployment.
    """

    # Create the deployment folder if it doesn't exist
    deployment_folder = os.path.join(os.path.dirname(__file__), DEPLOYMENT_DATA_FOLDER)

    if not os.path.exists(deployment_folder):
        os.makedirs(deployment_folder)

    # Derive version from current time
    version = str(int(time.time()))

    # Calculate max digits required for zero-padding
    with open("program.zip", "rb") as zip_file:
        zip_file_size = os.path.getsize("program.zip")
        num_chunks = zip_file_size // CHUNK_SIZE + 1

    num_digits = len(str(num_chunks))

    # Split the zip file into small chunks of data
    with open("program.zip", "rb") as zip_file:
        chunk_num = 0
        while True:
            chunk = zip_file.read(CHUNK_SIZE)
            if not chunk:
                break

            chunk_file_path = os.path.join(deployment_folder,
                                           f"{PROGRAM_NAME}_{version}_{str(chunk_num).zfill(num_digits)}")
            with open(chunk_file_path, "wb") as chunk_file:
                chunk_file.write(chunk)

            chunk_num += 1

    return f"{PROGRAM_NAME}_{version}"


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

    with open(file_path, 'rb') as file:
        file_data = file.read()

    signature = base64.b64decode(b64sig)

    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(e)
        return False


def sign_file(file_path):
    """
    Signs a file with the private key, and stores it alongside the file.

    :param file_path: The path to the file to sign.

    :return: The base64 encoded signature.
    """

    # Load the private key
    with open(os.path.join(os.path.dirname(__file__), PRIVATE_KEY), "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Sign the data
    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    b64sig = base64.b64encode(signature)

    # ensure the signature is valid
    assert verify_signature(file_path, b64sig)

    # Write the signature to a file
    with open(f"{file_path}.sig", "wb") as sig_file:
        sig_file.write(b64sig)

    return b64sig


def generate_deployment():
    """
    Generate a deployment manifest for the IoT device.

    This function creates a deployment manifest that includes information about the files
    to be deployed, their corresponding SHA256 hashes, and other metadata. The manifest is
    then signed with a private key for security.

    The function checks if the latest full hash is the same as the previous one.
    If it is, no action is taken to avoid unnecessary deployments.
    """
    full_hash = read_program()

    # do not do anything if the latest full hash is the exact same
    if os.path.exists(os.path.join(os.path.dirname(__file__), DEPLOYMENT_MANIFEST_FOLDER, "latest")):
        with open(os.path.join(os.path.dirname(__file__), DEPLOYMENT_MANIFEST_FOLDER, "latest"), "r") as f:
            if f.readlines()[2].split()[1] == full_hash:
                print("Latest deployment matches current deployment. No action taken.\n")
                return

    prefix = split_data()

    # create a list of files belonging to the deployment, and then calculate their sha256 hashes
    deployment_folder = os.path.join(os.path.dirname(__file__), DEPLOYMENT_DATA_FOLDER)

    # Create the deployment manifest folder if it doesn't exist
    manifest_folder = os.path.join(os.path.dirname(__file__), DEPLOYMENT_MANIFEST_FOLDER)

    if not os.path.exists(manifest_folder):
        os.makedirs(manifest_folder)

    deployment_files = [x for x in os.listdir(deployment_folder) if x.startswith(prefix)]
    deployment_hashes = []

    for file in deployment_files:
        with open(os.path.join(deployment_folder, file), "rb") as f:
            hash_object = hashlib.sha256(f.read())
            deployment_hashes.append(hash_object.hexdigest())

    print(f"Split and wrote deployment into {len(deployment_files)} chunks.\n")

    # write the deployment manifest
    manifest = os.path.join(manifest_folder, f"{prefix}")
    with open(manifest, "w") as f:
        # Deployment ID
        f.write(f"{prefix}\n")

        # ISO Timestamp
        f.write(f"{datetime.datetime.now().isoformat()}\n")

        f.write(f"program.zip {full_hash}\n")

        for i, file in enumerate(deployment_files):
            # SHA256, File name
            f.write(f"{deployment_hashes[i]} {file}\n")

    print("Wrote deployment manifest.\n")
    print(f"Deployment ID: {prefix}\n")

    latest = os.path.join(manifest_folder, "latest")

    # Update the "latest" deployment manifest to the current one by duplicating the file using os copy
    shutil.copy(manifest, latest)

    # Sign the deployment manifests with a private key
    sign_file(manifest)
    sign_file(latest)
    print("Signature OK.")


def cleanup():
    """
    Cleans up after the job is done.
    """
    if os.path.exists("program.zip"):
        os.remove("program.zip")

    print("Finished cleanup.")


def main():
    # Ensure keys are present
    if not os.path.exists(os.path.join(os.path.dirname(__file__), PRIVATE_KEY)):
        keys.generate_and_save_keys()

    # Create deployment zip file
    generate_deployment()


if __name__ == '__main__':
    try:
        main()
    finally:
        cleanup()
