from app import create_app

app = create_app()

if __name__ == "__main__":
    # threaded=True so the server can answer scan-progress polls while a scan
    # runs in a background thread (roadmap item 8).
    app.run(debug=True, port=5000, threaded=True)
