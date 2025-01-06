import logging
import os
from typing import Dict, Any
import hashlib
import requests
from my_proof.models.proof_response import ProofResponse

class Proof:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.proof_response = ProofResponse(dlp_id=config['dlp_id'])

    def generate(self) -> ProofResponse:
        try:
            """Generate proofs for all input files."""
            logging.info("Starting proof generation")

            ownership = 0
            authenticity = 0
            uniqueness = 0
            quality = 0
            file_hash: str | None = None
            hash_id: str | None = None

            agends_url = 'https://apparently-finer-hen.ngrok-free.app'

            if self.config['env'] == 'production':
                agends_url = "https://agends-be-production.up.railway.app" 
            elif self.config['env'] == 'staging':
                agends_url = "https://agends-be-staging.up.railway.app"

            input_files = os.listdir(self.config['input_dir'])
            # Expecting one zip file
            input_file = input_files[0]

            # Calculate SHA-256 hash of the input file
            sha256_hash = hashlib.sha256()
            with open(input_file, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block, 'binary')
            file_hash = sha256_hash.digest('base64')

            hash_response = requests.get(
                agends_url + '/vana-package-hash',
                headers={'Authorization': 'Bearer ' + self.config.get('agends_auth_token')},
                params={'hash': file_hash}
            )

            if hash_response.status_code == 200:
                data = hash_response.json()
                if data:
                    hash_id = data.get('id')

                    if data.get('validated', False):
                        ownership = 1.0
                        authenticity = 1.0
                        uniqueness = 1.0

                        file_size = os.path.getsize(input_file)

                        if file_size > 1024 * 1024:  # file size greater than 1 MB
                            quality = 1.0
                        elif file_size > 1024:
                            quality = 0.5
                        else: 
                            quality = 0

                        logging.info(f"Authentication Passed, Ownership Passed and Uniqueness Passed")
                    else:
                        ownership = 1.0
                        authenticity = 1.0
                        uniqueness = 0
                        quality = 0

                        logging.info(f"Authentication Passed and Ownership Passed")
                else: 
                    raise ValueError(f"Invalid File")
            else:
                raise ValueError(f"Failed to validate file with status code {hash_response.status_code}")
            
            self.proof_response.ownership = ownership
            self.proof_response.quality = quality
            self.proof_response.authenticity = authenticity
            self.proof_response.uniqueness = uniqueness

            self.proof_response.score = self.proof_response.quality
            self.proof_response.valid = authenticity > 0

            # Additional metadata about the proof, written onchain
            self.proof_response.metadata = {
                'dlp_id': self.config['dlp_id'],
                'file_hash': file_hash
            }

            mark_hash_valid_response = requests.post(
                agends_url + '/vana-package-hash/mark-valid',
                headers={'Authorization': 'Bearer ' + self.config.get('agends_auth_token')},
                params={'hash_id': hash_id}
            )

            if (mark_hash_valid_response.status_code != 201):
                raise ValueError('Something unexpected occurred!')

            return self.proof_response
        except Exception as e:
            raise ValueError(f"An error occurred during proof generation: {e}")