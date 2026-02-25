# Class Schedule & Homework App

A simple Flask application to track class schedules and homework deadlines. Built as a starting point for managing courses and assignments.

## Setup

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## Usage

### Usage

#### Standalone HTML (no installation required)

Simply open the file `templates/index.html` in your browser (double-click or use `File → Open...`).
Everything is contained in that single document — CSS and JavaScript are inlined and it keeps data using the browser's local storage.

#### Optional Python server

If you later install Python you can run the original Flask app instead:

```bash
cd flask_app
python -m venv venv
venv\Scripts\activate     # PowerShell
pip install -r requirements.txt
python app.py
```

Then go to `http://localhost:5000`. This version stores data in memory and is separate from the standalone HTML.

(The `static/` folder is no longer used by the standalone page and can be ignored.)
