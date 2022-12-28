from flask import Flask
from flask import render_template
from flask import request
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
from markupsafe import escape

app = Flask(__name__)

@app.route('/')
def index():
     return render_template('index.html')


@app.route('/check/<string:url>', methods=['GET'])
def check(url):
    # url = "hxxp://www.malwaredomainlist.com/"
    data = None
    if request.method == 'GET':
       with virustotal_python.Virustotal("5d5bfe2c2840146677ffa84db2c82a4f3cf7a4c721d20a30a7b678ed7966e801") as vtotal:
            try:
                resp = vtotal.request("urls", data={"url": url}, method="GET")
        # Safe encode URL in base64 format
        # https://developers.virustotal.com/reference/url
                url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
                report = vtotal.request(f"urls/{url_id}")
#         pprint(report.object_type)
                data = report.data
                pprint(report.data)
#         print(report.data.total_votes)
            except virustotal_python.VirustotalError as err:
                print(f"Failed to send URL: {url} for analysis and get the report: {err}")



       
    return f"{escape(data)}"
    # GET API with path param
@app.route('/gfg/<int:page>')
def gfg(page):
    return render_template('gfg.html', page=page)
if __name__ == '__main__':
    app.run()