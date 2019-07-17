# initialiseer de library's en app
from flask import Flask, jsonify

app = Flask(__name__)

# Geef het pad van de app aan
@app.route("/")
def hello():
    # de inhoud wordt vaak als json gelezen. Dit is geen Eis.
    inhoud = jsonify({
    "about":"Hello World!"
    })
    return inhoud

if __name__ == "__main__":
    # De debug modus op True betekent dat je de code kan veranderen terwijl de app loopt
    app.run(debug = True)