from flask import Flask, render_template
import os

app = Flask(__name__)


@app.route('/<string:filepath>/resultpage')
def result(filepath):
    #returngrapoh_path = "/static/MAWI100K-EFP-UDP.html"
    returngrapoh_path = "/static/mygraph.html"
    return render_template('resultpage.html',filepath=filepath, ret_gpath = returngrapoh_path)


@app.route('/<string:filepath>/filterpage')
def filter(filepath):
    return render_template('filterpage.html', filepath=filepath)

@app.route('/<string:uid>/fmpage')
def filemanagement(uid):
    testlist = ["1.pcap", "2.pcap", "3.pcap"]
    #testlist=[]
    userroot = "../user/user000/"
    return render_template('filepage.html', walkedlist = testlist, userroot=userroot, userid=uid)

if __name__ == "__main__":
    app.debug = True
    app.run()