from flask import Flask, render_template, request, jsonify
import threading
import time
import psycopg2 as pg
import requests
import json
from psycopg2.extras import RealDictCursor
import schedule

app = Flask(__name__)
fetching_in_progress = False

# Database connection details
DB_HOST = "localhost"
DB_NAME = "securin"
DB_USER = "postgres"
DB_PASSWORD = "Moulikd345"
DB_PORT = 5432

# Connect to the PostgreSQL database
def connect_to_database():
    try:
        conn = pg.connect(
            host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD, port=DB_PORT
        )
        return conn
    except Exception as e:
        print("Error connecting to database:", e)
        return None

# Fetch CVE details from the local database
@app.route('/', methods=['GET', 'POST'])
def index():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('resultsPerPage', 10))
    skip = (page - 1) * per_page
    conn = connect_to_database()
    if not conn:
        return jsonify({"error": "Failed to connect to database"}), 500

    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT COUNT(*) FROM cve")
    total_count = cur.fetchone()["count"]
    cur.execute("SELECT id, published, last_modified, vuln_status FROM cve OFFSET %s LIMIT %s", (skip, per_page))
    data = cur.fetchall()
    total_pages = (total_count + per_page - 1) // per_page

    # Format datetime objects as strings
    for item in data:
        item['published'] = item['published'].strftime('%Y-%m-%d')
        item['last_modified'] = item['last_modified'].strftime('%Y-%m-%d')

    conn.close()
    return render_template('Cve_maintable.html', data=data, page=page, per_page=per_page, total_count=total_count,
     total_pages=total_pages)

# Fetch CVE details by ID from the PostgreSQL database
@app.route("/details/<cve_id>")
def cve_detail(cve_id):
    conn = connect_to_database()
    if not conn:
        return jsonify({"error": "Failed to connect to database"}), 500
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT cve.*, cvss_metric.*, json_agg(row) AS criteria
            FROM cve
            LEFT JOIN cvss_metric ON cvss_metric.cve_id = cve.id
            LEFT JOIN (
                SELECT * FROM configuration WHERE cve_id = %s
            ) AS row ON row.cve_id = cve.id
            GROUP BY cve.id, cvss_metric.id
        """, (cve_id,))
        cve_details = cur.fetchone()
        cur.execute("SELECT * FROM cve WHERE id = %s", (cve_id,))
        cve_detail = cur.fetchone()
        # Handle case where CVE not found
        if not cve_details:
            return render_template('Cve_details.html', cve_details=None, cve_detail=None)
        # Format datetime objects as strings
        cve_details['published'] = cve_details['published'].strftime('%Y-%m-%d')
        cve_details['last_modified'] = cve_details['last_modified'].strftime('%Y-%m-%d')
    except (Exception, pg.Error) as error:
        # Handle database connection errors gracefully
        conn.rollback() if conn else None  # Rollback any changes if connection existed
        error_message = "Error fetching CVE details: " + str(error)
        return render_template('error.html', error_message=error_message)
    finally:
        # Always close the connection, even if no errors occur
        conn.close()
        return render_template('Cve_details.html', cve_details=cve_details, cve_detail=cve_detail)

@app.route("/cves/year/<int:year>", methods=["GET"])
def get_cves_by_year(year):
    try:
        # Connect to the database
        conn = pg.connect(
            host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD, port=DB_PORT
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Execute query to fetch CVE details by year
        cur.execute(
            """
            SELECT cve.id, cve.source_identifier, cve.published, cve.last_modified, cve.vuln_status,
                   cvss.base_score
            FROM cve
            LEFT JOIN cvss_metric AS cvss ON cvss.cve_id = cve.id
            WHERE EXTRACT(YEAR FROM cve.published) = %s
            ORDER BY cve.published DESC;
            """,
            (year,),
        )
        rows = cur.fetchall()

        # Format CVE details as JSON response
        cve_data = []
        for row in rows:
            cve = {
                "id": row[0],
                "sourceIdentifier": row[1],
                "published": str(row[2]),
                "lastModified": str(row[3]),
                "vulnStatus": row[4],
                "cvssScore": row[5] if row[5] else None,
            }
            cve_data.append(cve)

        # Close database connection
        conn.close()

        # Return JSON response with CVE details
        return jsonify({"cves": cve_data})

    except Exception as e:
        # Handle database connection or query errors
        return jsonify({"error": "Failed to fetch CVE details"}), 500

@app.route("/cves/score/<float:score>", methods=["GET"])
def get_cves_by_score(score):
    try:
        # Connect to the database
        conn = pg.connect(
            host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD, port=DB_PORT
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Execute query to fetch CVE details by score
        cur.execute(
            """
            SELECT cve.id, cve.source_identifier, cve.published, cve.last_modified, cve.vuln_status,
                   cvss.base_score
            FROM cve
            LEFT JOIN cvss_metric AS cvss ON cvss.cve_id = cve.id
            WHERE cvss.base_score = %s
            ORDER BY cve.published DESC;
            """,
            (score,),
        )
        rows = cur.fetchall()

        # Format CVE details as JSON response
        cve_data = []
        for row in rows:
            cve = {
                "id": row[0],
                "sourceIdentifier": row[1],
                "published": str(row[2]),
                "lastModified": str(row[3]),
                "vulnStatus": row[4],
                "cvssScore": row[5] if row[5] else None,
            }
            cve_data.append(cve)

        # Close database connection
        conn.close()

        # Return JSON response with CVE details
        return jsonify({"cves": cve_data})

    except Exception as e:
        # Handle database connection or query errors
        return jsonify({"error": "Failed to fetch CVE details"}), 500

@app.route("/cves/lastmodified/<int:days>", methods=["GET"])
def get_cves_last_modified(days):
    try:
        # Connect to the database
        conn = pg.connect(
            host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD, port=DB_PORT
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Calculate the date N days ago
        from datetime import datetime, timedelta
        cutoff_date = datetime.now() - timedelta(days=days)

        # Execute query to fetch CVE details last modified within N days
        cur.execute(
            """
            SELECT cve.id, cve.source_identifier, cve.published, cve.last_modified, cve.vuln_status,
                   cvss.base_score
            FROM cve
            LEFT JOIN cvss_metric AS cvss ON cvss.cve_id = cve.id
            WHERE cve.last_modified >= %s
            ORDER BY cve.published DESC;
            """,
            (cutoff_date,),
        )
        rows = cur.fetchall()

        # Format CVE details as JSON response
        cve_data = []
        for row in rows:
            cve = {
                "id": row[0],
                "sourceIdentifier": row[1],
                "published": str(row[2]),
                "lastModified": str(row[3]),
                "vulnStatus": row[4],
                "cvssScore": row[5] if row[5] else None,
            }
            cve_data.append(cve)

        # Close database connection
        conn.close()

        # Return JSON response with CVE details
        return jsonify({"cves": cve_data})

    except Exception as e:
        # Handle database connection or query errors
        return jsonify({"error": "Failed to fetch CVE details"}), 500


# Function to fetch data from the original database
def fetch_data():
    global fetching_in_progress
    fetching_in_progress = True
    nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    startIndex = read_start_index()
    try:
        while True:
            url = f"{nvd_base_url}?startIndex={startIndex}"
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            totalResults = data["totalResults"]
            resultsPerPage = data["resultsPerPage"]
            conn = pg.connect(
                host=DB_HOST,
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
                port=DB_PORT
            )
            cursor = conn.cursor()
            cursor.callproc('insert_cve_data', [json.dumps(data)])
            conn.commit()
            print(f"Stored procedure executed successfully. Data fetched: {startIndex + resultsPerPage}/{totalResults}")
            startIndex += resultsPerPage
            write_start_index(startIndex)
            conn.close()
            if startIndex >= totalResults:
                break
            time.sleep(1)
    except requests.exceptions.RequestException as e:
        print("An error occurred during the request:", e)
        print("Resuming from last fetched index:", startIndex)
        fetching_in_progress = False

# Placeholder functions for reading and writing start index
def read_start_index():
    try:
        with open("start_index.txt", "r") as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return 0

def write_start_index(startIndex):
    with open("start_index.txt", "w") as f:
        f.write(str(startIndex))

@app.route('/schedule', methods=['GET', 'POST'])
def schedule_cve_update():
    # Schedule the task to run every day at midnight
    print("Scheduling CVE update...")
    
    def job():
        fetch_data()
        
    schedule.every().day.at("00:00").do(job)
    
    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(1)
    
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.start()
    
    return "CVE update scheduled successfully."

@app.route('/fetch', methods=['GET', 'POST'])
def fetch():
    global fetching_in_progress
    if request.method == 'POST':
        if fetching_in_progress:
            return "Data fetching is already in progress."
        else:
            thread = threading.Thread(target=fetch_data)
            thread.start()
            return "Data fetching process started."
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
