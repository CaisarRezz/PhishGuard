from flask import jsonify

def api_success(data=None, message="Operation completed successfully", status_code=200):
    return jsonify({
        "success": True,
        "data": data,
        "message": message
    }), status_code

def api_error(message="An error occurred", data=None, status_code=400):
    return jsonify({
        "success": False,
        "data": data,
        "message": message
    }), status_code
