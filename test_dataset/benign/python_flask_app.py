from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', title='Trang chu')

@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    # Truy van an toan voi tham so hoa
    user = {"id": user_id, "name": "Nguyen Van A"}
    return jsonify(user)

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    if len(keyword) > 100:
        keyword = keyword[:100]
    return jsonify({"query": keyword, "results": []})

if __name__ == '__main__':
    app.run(debug=False, port=5000)
