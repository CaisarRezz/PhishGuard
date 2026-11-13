from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Halo! Flask berhasil berjalan di VS Code."

if __name__ == "_main_":
    app.run(debug=True)