import json
import logging
import os
import sys
import traceback
from typing import Dict, Any

from my_proof.proof import Proof

INPUT_DIR, OUTPUT_DIR = '/input', '/output'

logging.basicConfig(level=logging.INFO, format='%(message)s')


def load_config() -> Dict[str, Any]:
    """Load proof configuration from environment variables."""
    env = os.environ.get('ENV')
    dlp_id = 30

    if env == 'production':
        dlp_id = 0
    elif env == 'staging':
        dlp_id = 0

    config = {
        'dlp_id': dlp_id, 
        'input_dir': INPUT_DIR,
        'env': env,
        'agends_auth_token': os.environ.get('AGENDS_AUTH_TOKEN', None),
    }
    logging.info(f"Using config: {json.dumps(config, indent=2)}")
    return config


def run() -> None:
    """Generate proofs for all input files."""
    config = load_config()
    input_files_exist = os.path.isdir(INPUT_DIR) and bool(os.listdir(INPUT_DIR))

    if not input_files_exist:
        raise FileNotFoundError(f"No input files found in {INPUT_DIR}")

    proof = Proof(config)
    proof_response = proof.generate()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "results.json")
    with open(output_path, 'w') as f:
        json.dump(proof_response.dict(), f, indent=2)
    logging.info(f"Proof generation complete: {proof_response}")


if __name__ == "__main__":
    try:
        run()
    except Exception as e:
        logging.error(f"Error during proof generation: {e}")
        traceback.print_exc()
        sys.exit(1)
