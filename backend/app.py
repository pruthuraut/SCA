import os
import shutil
import tempfile
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from git import Repo
from sca_core import SoftwareCompositionAnalyzer

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

analyzer = SoftwareCompositionAnalyzer(logger=logger)

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

@app.route('/api/scan/upload', methods=['POST'])
def scan_upload():
    if 'files' not in request.files:
        return jsonify({"error": "No files provided"}), 400
    
    files = request.files.getlist('files')
    if not files:
        return jsonify({"error": "No files selected"}), 400

    # Create a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Save files
            for file in files:
                if file.filename:
                    file_path = os.path.join(temp_dir, file.filename)
                    file.save(file_path)
            
            # Run scan
            result = analyzer.scan_project(temp_dir, project_name="Uploaded Files")
            return jsonify(result), 200
            
        except Exception as e:
            logger.exception("Error processing upload scan")
            return jsonify({"error": str(e)}), 500

@app.route('/api/scan/github', methods=['POST'])
def scan_github():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400
    
    repo_url = data['url']
    
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            logger.info(f"Cloning {repo_url} into {temp_dir}")
            Repo.clone_from(repo_url, temp_dir)
            
            # Run scan
            project_name = repo_url.split('/')[-1].replace('.git', '')
            result = analyzer.scan_project(temp_dir, project_name=project_name)
            return jsonify(result), 200
            
        except Exception as e:
            logger.exception("Error processing GitHub scan")
            return jsonify({"error": f"Failed to clone or scan: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
