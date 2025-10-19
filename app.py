from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import csv
import io
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

# Create the Flask application
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Database setup
def init_db():
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    
    # Tenants table (organizations/hedge funds)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Users table (now linked to tenants)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id),
            UNIQUE(tenant_id, username),
            UNIQUE(tenant_id, email)
        )
    ''')
    
    # Trades table (replacing submissions)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS trades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            
            -- Core Trade Information
            side TEXT NOT NULL,
            trade_date DATE NOT NULL,
            settlement_date DATE NOT NULL,
            exec_time TIMESTAMP,
            
            -- Security Information
            security TEXT NOT NULL,
            isin TEXT,
            cusip TEXT,
            iss_country TEXT,
            maturity_date DATE,
            
            -- Trade Details
            quantity REAL NOT NULL,
            currency TEXT NOT NULL,
            price REAL NOT NULL,
            net_amount REAL,
            yield REAL,
            exec_venue TEXT,
            
            -- Counterparty Information
            broker_name TEXT NOT NULL,
            broker_code TEXT,
            
            -- Reference & Status
            trade_ref TEXT,
            seq_number TEXT,
            euroclear TEXT,
            status TEXT DEFAULT 'Pending',
            notes TEXT,
            
            -- Metadata
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (tenant_id) REFERENCES tenants (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()


# Decorator to require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Decorator to require admin role
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        # Check if user is admin
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user or user[0] != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('form_page'))
        
        return f(*args, **kwargs)
    return decorated_function


# Helper function to parse dates from various formats
def parse_date(date_str):
    """Parse date from multiple formats"""
    if not date_str or not date_str.strip():
        return None
    
    date_str = date_str.strip()
    # Try formats in priority order - US format (MM/DD) first for Bloomberg
    formats = [
        '%m/%d/%y',      # 09/13/22 (US format with 2-digit year) - BLOOMBERG DEFAULT
        '%m/%d/%Y',      # 09/13/2022 (US format with 4-digit year)
        '%Y-%m-%d',      # 2022-09-13 (ISO format)
        '%Y/%m/%d',      # 2022/09/13
        '%d/%m/%Y',      # 13/09/2022 (European format)
        '%d/%m/%y',      # 13/09/22 (European format with 2-digit year)
        '%y/%m/%d',      # 22/09/13
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).strftime('%Y-%m-%d')
        except ValueError:
            continue
    
    raise ValueError(f"Unable to parse date: {date_str}")


# Route: Home page
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('form_page'))
    return redirect(url_for('login'))


# Route: Organization registration (creates tenant + first admin user)
@app.route('/register-org', methods=['GET', 'POST'])
def register_org():
    if request.method == 'POST':
        org_name = request.form.get('org_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not org_name or not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register_org.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register_org.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register_org.html')
        
        password_hash = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('data.db')
            cursor = conn.cursor()
            
            # Create tenant
            cursor.execute('INSERT INTO tenants (name) VALUES (?)', (org_name,))
            tenant_id = cursor.lastrowid
            
            # Create first admin user for this tenant
            cursor.execute('''
                INSERT INTO users (tenant_id, username, email, password_hash, role)
                VALUES (?, ?, ?, ?, 'admin')
            ''', (tenant_id, username, email, password_hash))
            
            conn.commit()
            conn.close()
            
            flash(f'Organization "{org_name}" created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError:
            flash('Organization name already exists.', 'error')
            return render_template('register_org.html')
    
    return render_template('register_org.html')


# Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT users.id, users.password_hash, users.tenant_id, users.role, tenants.name 
            FROM users 
            JOIN tenants ON users.tenant_id = tenants.id 
            WHERE users.username = ?
        ''', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['tenant_id'] = user[2]
            session['role'] = user[3]
            session['tenant_name'] = user[4]
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('form_page'))
        else:
            flash('Invalid username or password.', 'error')
            return render_template('login.html')
    
    return render_template('login.html')


# Route: Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# Route: Show the trade entry form
@app.route('/form')
@login_required
def form_page():
    return render_template('form.html', 
                          username=session.get('username'),
                          tenant_name=session.get('tenant_name'),
                          role=session.get('role'))


# Route: Handle trade submission
@app.route('/submit', methods=['POST'])
@login_required
def submit_form():
    # Get form data
    side = request.form.get('side')
    trade_date = request.form.get('trade_date')
    settlement_date = request.form.get('settlement_date')
    exec_time = request.form.get('exec_time')
    
    security = request.form.get('security')
    isin = request.form.get('isin')
    cusip = request.form.get('cusip')
    iss_country = request.form.get('iss_country')
    maturity_date = request.form.get('maturity_date')
    
    quantity_str = request.form.get('quantity')
    currency = request.form.get('currency')
    price_str = request.form.get('price')
    net_amount_str = request.form.get('net_amount')
    yield_str = request.form.get('yield')
    exec_venue = request.form.get('exec_venue')
    
    broker_name = request.form.get('broker_name')
    broker_code = request.form.get('broker_code')
    
    trade_ref = request.form.get('trade_ref')
    seq_number = request.form.get('seq_number')
    euroclear = request.form.get('euroclear')
    status = request.form.get('status')
    notes = request.form.get('notes')
    
    # Validate required fields
    if not all([side, trade_date, settlement_date, security, quantity_str, currency, price_str, broker_name]):
        flash('Please fill in all required fields.', 'error')
        return redirect(url_for('form_page'))
    
    # Convert numeric fields
    try:
        quantity = float(quantity_str)
        price = float(price_str)
        
        # Auto-calculate net amount if not provided
        if net_amount_str and net_amount_str.strip():
            net_amount = float(net_amount_str)
        else:
            net_amount = quantity * price
            if side == 'S':  # Sell side is positive
                net_amount = abs(net_amount)
            else:  # Buy side is negative
                net_amount = -abs(net_amount)
        
        yield_val = float(yield_str) if yield_str and yield_str.strip() else None
        
    except ValueError:
        flash('Invalid numeric values entered.', 'error')
        return redirect(url_for('form_page'))
    
    # Validate dates
    try:
        trade_dt = datetime.strptime(trade_date, '%Y-%m-%d')
        settle_dt = datetime.strptime(settlement_date, '%Y-%m-%d')
        
        if settle_dt <= trade_dt:
            flash('Settlement date must be after trade date.', 'error')
            return redirect(url_for('form_page'))
    except ValueError:
        flash('Invalid date format.', 'error')
        return redirect(url_for('form_page'))
    
    # Convert empty strings to None for optional fields
    exec_time = exec_time if exec_time else None
    isin = isin if isin else None
    cusip = cusip if cusip else None
    iss_country = iss_country if iss_country else None
    maturity_date = maturity_date if maturity_date else None
    exec_venue = exec_venue if exec_venue else None
    broker_code = broker_code if broker_code else None
    trade_ref = trade_ref if trade_ref else None
    seq_number = seq_number if seq_number else None
    euroclear = euroclear if euroclear else None
    notes = notes if notes else None
    
    # Save to database
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO trades (
            tenant_id, user_id, side, trade_date, settlement_date, exec_time,
            security, isin, cusip, iss_country, maturity_date,
            quantity, currency, price, net_amount, yield, exec_venue,
            broker_name, broker_code,
            trade_ref, seq_number, euroclear, status, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        session['tenant_id'], session['user_id'], side, trade_date, settlement_date, exec_time,
        security, isin, cusip, iss_country, maturity_date,
        quantity, currency, price, net_amount, yield_val, exec_venue,
        broker_name, broker_code,
        trade_ref, seq_number, euroclear, status, notes
    ))
    conn.commit()
    conn.close()
    
    flash('Trade submitted successfully!', 'success')
    return redirect(url_for('success'))


# Route: Success page
@app.route('/success')
@login_required
def success():
    return render_template('success.html', 
                          username=session.get('username'),
                          tenant_name=session.get('tenant_name'),
                          role=session.get('role'))


# Route: View trades (filtered by tenant)
@app.route('/view')
@login_required
def view_submissions():
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            trades.id,
            trades.side,
            trades.trade_date,
            trades.security,
            trades.quantity,
            trades.currency,
            trades.price,
            trades.net_amount,
            trades.broker_name,
            trades.status,
            trades.created_at,
            users.username
        FROM trades 
        JOIN users ON trades.user_id = users.id
        WHERE trades.tenant_id = ? 
        ORDER BY trades.created_at DESC
    ''', (session['tenant_id'],))
    trades = cursor.fetchall()
    conn.close()
    
    return render_template('view.html', 
                          trades=trades, 
                          username=session.get('username'),
                          tenant_name=session.get('tenant_name'),
                          role=session.get('role'))


# Route: View single trade details
@app.route('/trade/<int:trade_id>')
@login_required
def trade_detail(trade_id):
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            trades.id,
            trades.side,
            trades.trade_date,
            trades.settlement_date,
            trades.exec_time,
            trades.security,
            trades.isin,
            trades.cusip,
            trades.iss_country,
            trades.maturity_date,
            trades.quantity,
            trades.currency,
            trades.price,
            trades.net_amount,
            trades.yield,
            trades.exec_venue,
            trades.broker_name,
            trades.broker_code,
            trades.trade_ref,
            trades.seq_number,
            trades.euroclear,
            trades.status,
            trades.notes,
            trades.created_at,
            users.username
        FROM trades 
        JOIN users ON trades.user_id = users.id
        WHERE trades.id = ? AND trades.tenant_id = ?
    ''', (trade_id, session['tenant_id']))
    
    trade_row = cursor.fetchone()
    conn.close()
    
    if not trade_row:
        flash('Trade not found.', 'error')
        return redirect(url_for('view_submissions'))
    
    # Convert to dictionary for easier template access
    trade = {
        'id': trade_row[0],
        'side': trade_row[1],
        'trade_date': trade_row[2],
        'settlement_date': trade_row[3],
        'exec_time': trade_row[4],
        'security': trade_row[5],
        'isin': trade_row[6],
        'cusip': trade_row[7],
        'iss_country': trade_row[8],
        'maturity_date': trade_row[9],
        'quantity': trade_row[10],
        'currency': trade_row[11],
        'price': trade_row[12],
        'net_amount': trade_row[13],
        'yield_val': trade_row[14],
        'exec_venue': trade_row[15],
        'broker_name': trade_row[16],
        'broker_code': trade_row[17],
        'trade_ref': trade_row[18],
        'seq_number': trade_row[19],
        'euroclear': trade_row[20],
        'status': trade_row[21],
        'notes': trade_row[22],
        'created_at': trade_row[23],
        'username': trade_row[24]
    }
    
    return render_template('trade_detail.html',
                          trade=trade,
                          username=session.get('username'),
                          tenant_name=session.get('tenant_name'),
                          role=session.get('role'))


# Route: Edit trade (GET - show form, POST - save changes)
@app.route('/trade/<int:trade_id>/edit', methods=['GET', 'POST'])
@login_required
def trade_edit(trade_id):
    if request.method == 'POST':
        # Get form data
        side = request.form.get('side')
        trade_date = request.form.get('trade_date')
        settlement_date = request.form.get('settlement_date')
        exec_time = request.form.get('exec_time')
        
        security = request.form.get('security')
        isin = request.form.get('isin')
        cusip = request.form.get('cusip')
        iss_country = request.form.get('iss_country')
        maturity_date = request.form.get('maturity_date')
        
        quantity_str = request.form.get('quantity')
        currency = request.form.get('currency')
        price_str = request.form.get('price')
        net_amount_str = request.form.get('net_amount')
        yield_str = request.form.get('yield')
        exec_venue = request.form.get('exec_venue')
        
        broker_name = request.form.get('broker_name')
        broker_code = request.form.get('broker_code')
        
        trade_ref = request.form.get('trade_ref')
        seq_number = request.form.get('seq_number')
        euroclear = request.form.get('euroclear')
        status = request.form.get('status')
        notes = request.form.get('notes')
        
        # Validate required fields
        if not all([side, trade_date, settlement_date, security, quantity_str, currency, price_str, broker_name]):
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('trade_edit', trade_id=trade_id))
        
        # Convert numeric fields
        try:
            quantity = float(quantity_str)
            price = float(price_str)
            
            # Auto-calculate net amount if not provided
            if net_amount_str and net_amount_str.strip():
                net_amount = float(net_amount_str)
            else:
                net_amount = quantity * price
                if side == 'S':
                    net_amount = abs(net_amount)
                else:
                    net_amount = -abs(net_amount)
            
            yield_val = float(yield_str) if yield_str and yield_str.strip() else None
            
        except ValueError:
            flash('Invalid numeric values entered.', 'error')
            return redirect(url_for('trade_edit', trade_id=trade_id))
        
        # Validate dates
        try:
            trade_dt = datetime.strptime(trade_date, '%Y-%m-%d')
            settle_dt = datetime.strptime(settlement_date, '%Y-%m-%d')
            
            if settle_dt <= trade_dt:
                flash('Settlement date must be after trade date.', 'error')
                return redirect(url_for('trade_edit', trade_id=trade_id))
        except ValueError:
            flash('Invalid date format.', 'error')
            return redirect(url_for('trade_edit', trade_id=trade_id))
        
        # Convert empty strings to None for optional fields
        exec_time = exec_time if exec_time else None
        isin = isin if isin else None
        cusip = cusip if cusip else None
        iss_country = iss_country if iss_country else None
        maturity_date = maturity_date if maturity_date else None
        exec_venue = exec_venue if exec_venue else None
        broker_code = broker_code if broker_code else None
        trade_ref = trade_ref if trade_ref else None
        seq_number = seq_number if seq_number else None
        euroclear = euroclear if euroclear else None
        notes = notes if notes else None
        
        # Update in database
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE trades SET
                side = ?, trade_date = ?, settlement_date = ?, exec_time = ?,
                security = ?, isin = ?, cusip = ?, iss_country = ?, maturity_date = ?,
                quantity = ?, currency = ?, price = ?, net_amount = ?, yield = ?, exec_venue = ?,
                broker_name = ?, broker_code = ?,
                trade_ref = ?, seq_number = ?, euroclear = ?, status = ?, notes = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND tenant_id = ?
        ''', (
            side, trade_date, settlement_date, exec_time,
            security, isin, cusip, iss_country, maturity_date,
            quantity, currency, price, net_amount, yield_val, exec_venue,
            broker_name, broker_code,
            trade_ref, seq_number, euroclear, status, notes,
            trade_id, session['tenant_id']
        ))
        conn.commit()
        conn.close()
        
        flash('Trade updated successfully!', 'success')
        return redirect(url_for('trade_detail', trade_id=trade_id))
    
    # GET request - show the edit form
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            trades.id, trades.side, trades.trade_date, trades.settlement_date, trades.exec_time,
            trades.security, trades.isin, trades.cusip, trades.iss_country, trades.maturity_date,
            trades.quantity, trades.currency, trades.price, trades.net_amount, trades.yield, trades.exec_venue,
            trades.broker_name, trades.broker_code,
            trades.trade_ref, trades.seq_number, trades.euroclear, trades.status, trades.notes
        FROM trades 
        WHERE trades.id = ? AND trades.tenant_id = ?
    ''', (trade_id, session['tenant_id']))
    
    trade_row = cursor.fetchone()
    conn.close()
    
    if not trade_row:
        flash('Trade not found.', 'error')
        return redirect(url_for('view_submissions'))
    
    # Format exec_time for datetime-local input if present
    exec_time_formatted = ''
    if trade_row[4]:
        try:
            dt = datetime.strptime(trade_row[4], '%Y-%m-%d %H:%M:%S')
            exec_time_formatted = dt.strftime('%Y-%m-%dT%H:%M')
        except:
            pass
    
    # Convert to dictionary
    trade = {
        'id': trade_row[0],
        'side': trade_row[1],
        'trade_date': trade_row[2],
        'settlement_date': trade_row[3],
        'exec_time': trade_row[4],
        'exec_time_formatted': exec_time_formatted,
        'security': trade_row[5],
        'isin': trade_row[6],
        'cusip': trade_row[7],
        'iss_country': trade_row[8],
        'maturity_date': trade_row[9],
        'quantity': trade_row[10],
        'currency': trade_row[11],
        'price': trade_row[12],
        'net_amount': trade_row[13],
        'yield_val': trade_row[14],
        'exec_venue': trade_row[15],
        'broker_name': trade_row[16],
        'broker_code': trade_row[17],
        'trade_ref': trade_row[18],
        'seq_number': trade_row[19],
        'euroclear': trade_row[20],
        'status': trade_row[21],
        'notes': trade_row[22]
    }
    
    return render_template('trade_edit.html',
                          trade=trade,
                          username=session.get('username'),
                          tenant_name=session.get('tenant_name'),
                          role=session.get('role'))


# Route: Import trades page
@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_trades():
    if request.method == 'GET':
        return render_template('import_trades.html',
                              username=session.get('username'),
                              tenant_name=session.get('tenant_name'),
                              role=session.get('role'))
    
    # Handle file upload
    if 'file' not in request.files:
        flash('No file uploaded.', 'error')
        return redirect(url_for('import_trades'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('import_trades'))
    
    if not file.filename.endswith('.csv'):
        flash('Please upload a CSV file.', 'error')
        return redirect(url_for('import_trades'))
    
    try:
        # Read CSV file - try multiple encodings
        raw_content = file.stream.read()
        csv_content = None
        
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        for encoding in encodings:
            try:
                csv_content = raw_content.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        
        if csv_content is None:
            flash('Unable to decode file. Please ensure it is a valid CSV file.', 'error')
            return redirect(url_for('import_trades'))
        
        lines = csv_content.split('\n')
        
        # Column name mappings (Bloomberg -> our format)
        column_mappings = {
            'side': ['side'],
            'trade_date': ['trade dt', 'trade_dt', 'trade date', 'tradedate', 'trade_date'],
            'settlement_date': ['setdt yr', 'setdt', 'set dt', 'settlement date', 'settlement_date', 'settledate', 'settle dt'],
            'security': ['security', 'sec'],
            'quantity': ['quantity', 'qty'],
            'currency': ['curncy', 'currency', 'curr', 'ccy'],
            'price': ['price', 'px'],
            'broker_name': ['brkrname', 'broker name', 'broker_name', 'broker'],
            'isin': ['isin'],
            'cusip': ['cusip'],
            'iss_country': ['iss country', 'iss_country', 'country'],
            'maturity_date': ['mat dt', 'maturity date', 'maturity_date', 'mat_dt'],
            'exec_time': ['exec time (gmt)', 'exec time', 'exec_time', 'execution time'],
            'exec_venue': ['venue', 'exec venue', 'exec_venue'],
            'yield': ['yield', 'yld'],
            'broker_code': ['brkr', 'broker code', 'broker_code'],
            'trade_ref': ['ts tkt#', 'trade ref', 'trade_ref', 'ref', 'ticket'],
            'seq_number': ['seq#', 'seq', 'sequence'],
            'status': ['status'],
            'notes': ['notes', 'comments']
        }
        
        # Find the header row (first row that contains key column names)
        header_row_idx = -1
        header_row = None
        key_indicators = ['side', 'quantity', 'security', 'price']
        
        for idx, line in enumerate(lines):
            if not line.strip():
                continue
            # Try to parse as CSV
            cells = list(csv.reader([line]))[0]
            # Normalize cell names
            normalized_cells = [cell.strip().lower() for cell in cells]
            # Check if this looks like a header row
            matches = sum(1 for indicator in key_indicators if any(indicator in cell for cell in normalized_cells))
            if matches >= 3:  # At least 3 key columns present
                header_row_idx = idx
                header_row = cells
                break
        
        if header_row_idx == -1:
            flash('Could not find valid header row in CSV file. Please ensure the file contains column headers.', 'error')
            return redirect(url_for('import_trades'))
        
        # Parse CSV starting from header row
        csv_lines = lines[header_row_idx:]
        csv_stream = io.StringIO('\n'.join(csv_lines))
        csv_reader = csv.DictReader(csv_stream)
        
        # Normalize fieldnames and create mapping
        # IMPORTANT: Strip spaces and normalize
        normalized_headers = {}
        for h in csv_reader.fieldnames:
            if h:
                # Clean the header name
                clean_name = h.strip().lower()
                normalized_headers[clean_name] = h
        
        # Map Bloomberg columns to our expected columns
        column_map = {}
        for our_col, possible_names in column_mappings.items():
            for possible_name in possible_names:
                if possible_name in normalized_headers:
                    column_map[our_col] = normalized_headers[possible_name]
                    break
        
        # Check required columns
        required_cols = ['side', 'trade_date', 'settlement_date', 'security', 
                        'quantity', 'currency', 'price', 'broker_name']
        missing_cols = [col for col in required_cols if col not in column_map]
        
        if missing_cols:
            flash(f'Missing required columns: {", ".join(missing_cols)}. Found columns: {", ".join(normalized_headers.keys())}', 'error')
            return redirect(url_for('import_trades'))
        
        # Parse and validate trades
        trades_to_import = []
        errors = []
        row_num = header_row_idx + 1
        
        for row in csv_reader:
            row_num += 1
            
            # Skip empty rows
            if not any(row.values()):
                continue
            
            # Map columns using our mapping
            mapped_row = {}
            for our_col, original_col in column_map.items():
                mapped_row[our_col] = row.get(original_col, '')
            
            try:
                # Validate required fields
                side = mapped_row.get('side', '').strip().upper()
                if side not in ['B', 'S']:
                    errors.append(f"Row {row_num}: Invalid side '{side}' (must be B or S)")
                    continue
                
                trade_date = parse_date(mapped_row.get('trade_date'))
                settlement_date = parse_date(mapped_row.get('settlement_date'))
                
                # Validate settlement date > trade date
                trade_dt = datetime.strptime(trade_date, '%Y-%m-%d')
                settle_dt = datetime.strptime(settlement_date, '%Y-%m-%d')
                if settle_dt <= trade_dt:
                    errors.append(f"Row {row_num}: Settlement date ({settlement_date}) must be after trade date ({trade_date})")
                    continue
                
                security = mapped_row.get('security', '').strip()
                if not security:
                    errors.append(f"Row {row_num}: Security is required")
                    continue
                
                quantity = float(mapped_row.get('quantity', '0').replace(',', ''))
                currency = mapped_row.get('currency', '').strip().upper()
                price = float(mapped_row.get('price', '0').replace(',', ''))
                broker_name = mapped_row.get('broker_name', '').strip()
                
                if not broker_name:
                    errors.append(f"Row {row_num}: Broker name is required")
                    continue
                
                # Calculate net amount
                net_amount = quantity * price
                if side == 'S':
                    net_amount = abs(net_amount)
                else:
                    net_amount = -abs(net_amount)
                
                # Optional fields
                exec_time_str = mapped_row.get('exec_time', '').strip()
                exec_time = None
                if exec_time_str:
                    try:
                        exec_time = datetime.strptime(exec_time_str, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        try:
                            exec_time = datetime.strptime(exec_time_str, '%m/%d/%Y %H:%M').strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            pass
                
                maturity_date = parse_date(mapped_row.get('maturity_date', ''))
                
                yield_val = None
                yield_str = mapped_row.get('yield', '').strip()
                if yield_str:
                    try:
                        yield_val = float(yield_str.replace(',', ''))
                    except:
                        pass
                
                trade_data = {
                    'side': side,
                    'trade_date': trade_date,
                    'settlement_date': settlement_date,
                    'exec_time': exec_time,
                    'security': security,
                    'isin': mapped_row.get('isin', '').strip() or None,
                    'cusip': mapped_row.get('cusip', '').strip() or None,
                    'iss_country': mapped_row.get('iss_country', '').strip() or None,
                    'maturity_date': maturity_date,
                    'quantity': quantity,
                    'currency': currency,
                    'price': price,
                    'net_amount': net_amount,
                    'yield': yield_val,
                    'exec_venue': mapped_row.get('exec_venue', '').strip() or None,
                    'broker_name': broker_name,
                    'broker_code': mapped_row.get('broker_code', '').strip() or None,
                    'trade_ref': mapped_row.get('trade_ref', '').strip() or None,
                    'seq_number': mapped_row.get('seq_number', '').strip() or None,
                    'euroclear': mapped_row.get('euroclear', '').strip() or None,
                    'status': mapped_row.get('status', 'Pending').strip() or 'Pending',
                    'notes': mapped_row.get('notes', '').strip() or None
                }
                
                trades_to_import.append(trade_data)
                
            except ValueError as e:
                errors.append(f"Row {row_num}: {str(e)}")
            except Exception as e:
                errors.append(f"Row {row_num}: Error processing row - {str(e)}")
        
        # If there are errors, show them
        if errors:
            error_msg = f"Found {len(errors)} error(s) in CSV file: " + " | ".join(errors[:5])
            if len(errors) > 5:
                error_msg += f" ... and {len(errors) - 5} more errors"
            flash(error_msg, 'error')
            return redirect(url_for('import_trades'))
        
        # If no trades to import
        if not trades_to_import:
            flash('No valid trades found in CSV file.', 'warning')
            return redirect(url_for('import_trades'))
        
        # Insert trades into database
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        
        imported_count = 0
        for trade in trades_to_import:
            try:
                cursor.execute('''
                    INSERT INTO trades (
                        tenant_id, user_id, side, trade_date, settlement_date, exec_time,
                        security, isin, cusip, iss_country, maturity_date,
                        quantity, currency, price, net_amount, yield, exec_venue,
                        broker_name, broker_code,
                        trade_ref, seq_number, euroclear, status, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session['tenant_id'], session['user_id'],
                    trade['side'], trade['trade_date'], trade['settlement_date'], trade['exec_time'],
                    trade['security'], trade['isin'], trade['cusip'], trade['iss_country'], trade['maturity_date'],
                    trade['quantity'], trade['currency'], trade['price'], trade['net_amount'], 
                    trade['yield'], trade['exec_venue'],
                    trade['broker_name'], trade['broker_code'],
                    trade['trade_ref'], trade['seq_number'], trade['euroclear'], trade['status'], trade['notes']
                ))
                imported_count += 1
            except Exception as e:
                errors.append(f"Error importing trade: {str(e)}")
        
        conn.commit()
        conn.close()
        
        if imported_count > 0:
            flash(f'Successfully imported {imported_count} trade(s)!', 'success')
            return redirect(url_for('view_submissions'))
        else:
            flash('No trades were imported. Please check the file format.', 'error')
            return redirect(url_for('import_trades'))
            
    except Exception as e:
        flash(f'Error processing file: {str(e)}', 'error')
        return redirect(url_for('import_trades'))


# Route: Download CSV template
@app.route('/download-template')
@login_required
def download_template():
    # Create CSV template with headers
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    headers = [
        'side', 'trade_date', 'settlement_date', 'security', 'quantity', 
        'currency', 'price', 'broker_name', 'isin', 'cusip', 'iss_country',
        'maturity_date', 'exec_time', 'exec_venue', 'yield', 'broker_code',
        'trade_ref', 'seq_number', 'euroclear', 'status', 'notes'
    ]
    writer.writerow(headers)
    
    # Write example row
    example = [
        'B', '2024-01-15', '2024-01-17', 'FSK 3 1/8 10/12/28', '5250000', 
        'USD', '99.682', 'ISRAEL BROKERAGE INV', 'US302635AK33', '302635AK3', 
        'US', '2028-10-12', '2024-01-15 07:12:00', '', '3.176', 'IBI',
        'FIT:20240115:3739:5:65915', '65915', 'ECLR/46605', 'Pending', ''
    ]
    writer.writerow(example)
    
    # Prepare download
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='trade_import_template.csv'
    )


# Route: User management (admin only)
@app.route('/users')
@login_required
@admin_required
def manage_users():
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, username, email, role, created_at 
        FROM users 
        WHERE tenant_id = ?
        ORDER BY created_at DESC
    ''', (session['tenant_id'],))
    users = cursor.fetchall()
    conn.close()
    
    return render_template('manage_users.html', 
                          users=users,
                          username=session.get('username'),
                          tenant_name=session.get('tenant_name'),
                          role=session.get('role'))


# Route: Add user (admin only)
@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if not username or not email or not password or not role:
            flash('All fields are required.', 'error')
            return render_template('add_user.html',
                                 username=session.get('username'),
                                 tenant_name=session.get('tenant_name'),
                                 role=session.get('role'))
        
        if role not in ['admin', 'user']:
            flash('Invalid role.', 'error')
            return render_template('add_user.html',
                                 username=session.get('username'),
                                 tenant_name=session.get('tenant_name'),
                                 role=session.get('role'))
        
        password_hash = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('data.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (tenant_id, username, email, password_hash, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['tenant_id'], username, email, password_hash, role))
            conn.commit()
            conn.close()
            
            flash(f'User "{username}" created successfully.', 'success')
            return redirect(url_for('manage_users'))
            
        except sqlite3.IntegrityError:
            flash('Username or email already exists in your organization.', 'error')
            return render_template('add_user.html',
                                 username=session.get('username'),
                                 tenant_name=session.get('tenant_name'),
                                 role=session.get('role'))
    
    return render_template('add_user.html',
                          username=session.get('username'),
                          tenant_name=session.get('tenant_name'),
                          role=session.get('role'))


# Run the application
if __name__ == '__main__':
    app.run(debug=True, port=5000)