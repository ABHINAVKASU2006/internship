from flask import Flask, request, jsonify
from pyzbar.pyzbar import decode
from PIL import Image

import io

app = Flask(__name__)

@app.route('/decode', methods=['POST'])
def decode_qr():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    img = Image.open(file.stream)
    decoded_objects = decode(img)

    if decoded_objects:
        qr_data = decoded_objects[0].data.decode("utf-8")
        return jsonify({"qr_code": qr_data})
    else:
        return jsonify({"error": "QR code not found"}), 404

if __name__ == '__main__':
    app.run(port=5001)
